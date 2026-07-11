// Package github ingests GitHub organization audit-log entries into the
// corroborate vocabulary: each entry becomes a record-side
// corroborate.Record, and actor activity is windowed into
// corroborate.Sessions with whatever binding the actor identity supports.
//
// Input is the audit log as GitHub serves it — the org audit-log API's
// JSON array or a JSONL export — via io.Reader, so the same code ingests
// a saved API page, a streamed export, or a future live fetcher. Every
// entry's provenance digest covers its exact raw JSON bytes as ingested.
//
// Attribution shape, which differs from CloudTrail in a useful way: the
// audit log's actor is an authenticated GitHub identity. A human username
// IS the named human (actor-identity binding); a bot or App actor
// ("dependabot[bot]", an OAuth app) is an agent fingerprint that binds to
// a human only through an explicit installation mapping the operator
// provides — exactly the convention the product checks.
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/ingest"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// Org names the organization the log belongs to; it anchors locators
	// so provenance says where an entry can be re-fetched.
	Org string

	// AppHumans maps bot/App actor logins to the human accountable for
	// them ("ci-deployer[bot]" → "alice@example.com") — the GitHub
	// equivalent of an STS SourceIdentity convention. Unmapped bots stay
	// unattributed, which downstream treats as a finding.
	AppHumans map[string]string

	// Bots marks additional actor logins as agents when the "[bot]"
	// suffix heuristic isn't enough (machine users with plain logins).
	Bots []string

	// SessionGap splits an actor's activity into separate Sessions after
	// this much silence. Defaults to 30 minutes, matching the cloudtrail
	// ingester.
	SessionGap time.Duration

	// IsProduction marks targets inside the production scope (e.g. the
	// repos that deploy). Nil means nothing is production-touching.
	IsProduction func(target string) bool
}

const defaultSessionGap = 30 * time.Minute

// Result is one audit-log ingestion's output.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester parses GitHub audit-log JSON into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.SessionGap <= 0 {
		opts.SessionGap = defaultSessionGap
	}
	return &Ingester{log: logger.With("component", "ingest-github"), opts: opts}
}

// IngestFile ingests one audit-log file (API page or export).
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open github audit log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f)
}

// Ingest reads audit-log entries from r: either a JSON array (the API
// response shape) or JSONL (one entry per line, the export shape).
func (g *Ingester) Ingest(r io.Reader) (Result, error) {
	raws, badLines, err := ingest.SplitJSONArrayOrLines(r)
	if err != nil {
		return Result{}, err
	}
	if badLines > 0 {
		g.log.Warn("skipped unparseable github audit lines", "lines", badLines)
	}

	var (
		records []corroborate.Record
		byActor = make(map[string][]corroborate.Record)
		skipped int
	)
	for _, raw := range raws {
		rec, ok := g.record(raw)
		if !ok {
			skipped++
			continue
		}
		records = append(records, rec)
		byActor[rec.Principal] = append(byActor[rec.Principal], rec)
	}
	if skipped > 0 {
		g.log.Warn("skipped github audit entries without id/action/actor", "entries", skipped)
	}

	sessions := g.sessions(byActor)
	g.log.Info("ingested github audit log",
		"org", g.opts.Org, "records", len(records), "sessions", len(sessions))
	return Result{Records: records, Sessions: sessions}, nil
}

// entry is the slice of a GitHub audit-log entry this ingester reads.
// The schema varies by action; absent fields are zero.
type entry struct {
	DocumentID string `json:"_document_id"`
	Action     string `json:"action"`
	Actor      string `json:"actor"`
	ActorIsBot bool   `json:"actor_is_bot"`
	// Timestamps are millisecond epochs in both API and export shapes.
	Timestamp int64 `json:"@timestamp"`
	CreatedAt int64 `json:"created_at"`
	// Target fields; which are present depends on the action.
	Org   string `json:"org"`
	Repo  string `json:"repo"`
	Team  string `json:"team"`
	User  string `json:"user"`
	OAuth string `json:"oauth_application"`
}

func (e *entry) at() time.Time {
	ms := e.Timestamp
	if ms == 0 {
		ms = e.CreatedAt
	}
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// record maps one raw entry onto the corroborate vocabulary; false means
// the entry lacks the identity fields a Record cannot exist without.
func (g *Ingester) record(raw json.RawMessage) (corroborate.Record, bool) {
	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return corroborate.Record{}, false
	}
	if e.DocumentID == "" || e.Action == "" || e.Actor == "" {
		return corroborate.Record{}, false
	}

	var targets []string
	for _, t := range []string{e.Repo, e.Team, e.User, e.Org} {
		if t != "" {
			targets = append(targets, t)
		}
	}
	rec := corroborate.Record{
		ID:         e.DocumentID,
		Source:     corroborate.SourceGitHubAudit,
		Operation:  "github-audit:" + e.Action,
		Principal:  e.Actor,
		Targets:    targets,
		RecordedAt: e.at(),
		Raw: corroborate.Provenance{
			Locator: "github-audit:" + g.opts.Org + "#" + e.DocumentID,
			Digest:  corroborate.DigestHex(raw),
		},
	}
	// A mapped bot names its human on every event it emits: the actor login
	// is on the entry and the installation mapping is deterministic, so this
	// is per-event identity — the GitHub analogue of STS SourceIdentity, and
	// what lets a mapped bot's production write be accountable rather than
	// unattributed.
	if g.isBot(e.Actor) {
		rec.SourceIdentity = g.opts.AppHumans[e.Actor]
	}
	if g.opts.IsProduction != nil {
		for _, t := range targets {
			if g.opts.IsProduction(t) {
				rec.ProductionTouching = true
				break
			}
		}
	}
	return rec, true
}

// sessions windows each actor's activity and binds what the identity
// supports: humans bind to themselves (the platform authenticated them),
// bots bind only through the operator's installation mapping.
func (g *Ingester) sessions(byActor map[string][]corroborate.Record) []corroborate.Session {
	var out []corroborate.Session
	for actor, recs := range byActor {
		sort.Slice(recs, func(i, j int) bool { return recs[i].RecordedAt.Before(recs[j].RecordedAt) })
		start := 0
		for i := 1; i <= len(recs); i++ {
			if i < len(recs) && recs[i].RecordedAt.Sub(recs[i-1].RecordedAt) <= g.opts.SessionGap {
				continue
			}
			out = append(out, g.session(actor, recs[start:i]))
			start = i
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (g *Ingester) session(actor string, window []corroborate.Record) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	s := corroborate.Session{
		ID:          "github:" + actor + "@" + first.RecordedAt.UTC().Format(time.RFC3339),
		Agent:       actor,
		StartedAt:   first.RecordedAt,
		EndedAt:     last.RecordedAt,
		Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
	}

	evidence := make([]string, 0, len(window))
	for _, r := range window {
		evidence = append(evidence, r.ID)
	}

	switch {
	case g.isBot(actor):
		if human := g.opts.AppHumans[actor]; human != "" {
			s.Human = human
			s.Attribution = corroborate.Attribution{Method: corroborate.AttrGitHubApp, Evidence: evidence}
		}
	case g.isHumanActor(actor):
		// The platform authenticated this username; the actor IS the human.
		s.Human = actor
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrActorIdentity, Evidence: evidence}
	default:
		// "ghost" and the org login fall through to unattributed (below).
	}
	return s
}

func (g *Ingester) isBot(actor string) bool {
	if strings.HasSuffix(actor, "[bot]") {
		return true
	}
	for _, b := range g.opts.Bots {
		if actor == b {
			return true
		}
	}
	return false
}

// isHumanActor reports whether the audit actor names a person. GitHub's
// "ghost" is the sentinel for a deleted or otherwise unattributable user
// (validated against a real org audit log: it appears as the actor on
// system-attributed events like billing changes), and the org login
// itself appears as the actor on org-level system events
// (org.codespaces_ownership_updated et al). Neither is an operator, so
// binding them as a named human would fabricate attribution.
func (g *Ingester) isHumanActor(actor string) bool {
	return actor != "" && actor != "ghost" && actor != g.opts.Org
}
