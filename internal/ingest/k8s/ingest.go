// Package k8s ingests Kubernetes audit events (audit.k8s.io/v1) into the
// corroborate vocabulary: each effective request becomes a record-side
// corroborate.Record, and per-user activity is windowed into
// corroborate.Sessions with the binding the cluster's conventions earn.
//
// Input is what audit backends actually emit: the log backend's JSONL
// (one Event per line) or the webhook backend's EventList, via io.Reader.
// The event schema is declared locally on purpose — the repo's hard rule
// bans k8s.io imports, and this ingester needs six fields, not a client
// machinery.
//
// The attribution convention this stream supports mirrors STS
// SourceIdentity exactly: an agent authenticates as its own
// ServiceAccount and impersonates the human it works for
// (Impersonate-User), so every audit event carries both identities —
// user.username (the agent's credential) and impersonatedUser.username
// (the human). A cluster that grants agents impersonate RBAC gets
// per-event human binding; one that hands agents bare SA tokens gets
// unattributed sessions, which is the finding.
package k8s

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// Cluster names the cluster the log came from; it anchors locators so
	// provenance says where an auditID can be re-fetched.
	Cluster string

	// SessionGap splits a user's activity into separate Sessions after
	// this much silence. Defaults to 30 minutes, matching the other
	// record-side ingesters.
	SessionGap time.Duration

	// IsProduction marks targets inside the production scope (e.g.
	// "prod/deployments/api"). Nil means nothing is production-touching.
	IsProduction func(target string) bool
}

const defaultSessionGap = 30 * time.Minute

// Result is one audit-log ingestion's output.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester parses Kubernetes audit JSON into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.Cluster == "" {
		opts.Cluster = "cluster"
	}
	if opts.SessionGap <= 0 {
		opts.SessionGap = defaultSessionGap
	}
	return &Ingester{log: logger.With("component", "ingest-k8s"), opts: opts}
}

// IngestFile ingests one audit log file.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open k8s audit log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f)
}

// event is the slice of audit.k8s.io/v1 Event this ingester reads,
// declared locally (no k8s.io imports, by hard rule).
type event struct {
	Kind       string `json:"kind"` // "Event" or "EventList"
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	RequestURI string `json:"requestURI"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceived time.Time `json:"requestReceivedTimestamp"`
	StageTimestamp  time.Time `json:"stageTimestamp"`
}

func (e *event) at() time.Time {
	if !e.StageTimestamp.IsZero() {
		return e.StageTimestamp
	}
	return e.RequestReceived
}

// effective reports whether this event is one completed, successful
// request — the only shape that becomes a Record. RequestReceived stages
// duplicate ResponseComplete ones; denied/failed requests (4xx/5xx)
// changed nothing, so corroborating them would let a denied attempt
// "corroborate" a claim of success. A missing user.username (anonymous
// or stripped events) yields no usable principal, so it is dropped too —
// a Record with an empty Principal can be neither attributed nor joined.
func (e *event) effective() bool {
	if e.Stage != "ResponseComplete" || e.AuditID == "" || e.Verb == "" || e.User.Username == "" {
		return false
	}
	return e.ResponseStatus == nil || e.ResponseStatus.Code < 400
}

// Ingest reads audit events from r: JSONL (log backend) or an EventList
// (webhook backend).
func (g *Ingester) Ingest(r io.Reader) (Result, error) {
	raws, badLines, err := splitEvents(r)
	if err != nil {
		return Result{}, err
	}
	if badLines > 0 {
		g.log.Warn("skipped unparseable k8s audit lines", "lines", badLines)
	}

	var (
		records = []corroborate.Record{}
		byUser  = make(map[string][]userEvent)
		skipped int
	)
	for _, raw := range raws {
		var e event
		if err := json.Unmarshal(raw, &e); err != nil {
			skipped++
			continue
		}
		if !e.effective() {
			continue
		}
		rec := g.record(&e, raw)
		records = append(records, rec)
		byUser[e.User.Username] = append(byUser[e.User.Username], userEvent{rec: rec, ev: e})
	}
	if skipped > 0 {
		g.log.Warn("skipped undecodable k8s audit events", "events", skipped)
	}

	sessions := g.sessions(byUser)
	g.log.Info("ingested k8s audit log",
		"cluster", g.opts.Cluster, "records", len(records), "sessions", len(sessions))
	return Result{Records: records, Sessions: sessions}, nil
}

func (g *Ingester) record(e *event, raw []byte) corroborate.Record {
	op := "k8s-audit:" + e.Verb
	var targets []string
	if e.ObjectRef != nil && e.ObjectRef.Resource != "" {
		op += ":" + e.ObjectRef.Resource
		if e.ObjectRef.Subresource != "" {
			op += "/" + e.ObjectRef.Subresource
		}
		target := e.ObjectRef.Resource
		if e.ObjectRef.Namespace != "" {
			target = e.ObjectRef.Namespace + "/" + target
		}
		if e.ObjectRef.Name != "" {
			target += "/" + e.ObjectRef.Name
		}
		targets = append(targets, target)
	} else if e.RequestURI != "" {
		targets = append(targets, e.RequestURI)
	}

	rec := corroborate.Record{
		ID:         e.AuditID,
		Source:     corroborate.SourceK8sAudit,
		Operation:  op,
		Principal:  e.User.Username,
		Targets:    targets,
		RecordedAt: e.at(),
		Raw: corroborate.Provenance{
			Locator: "k8s-audit:" + g.opts.Cluster + "#" + e.AuditID,
			Digest:  corroborate.DigestHex(raw),
		},
	}
	if e.ImpersonatedUser != nil {
		// The same slot STS SourceIdentity uses: the human the credential
		// session names on every event.
		rec.SourceIdentity = e.ImpersonatedUser.Username
	}
	if g.opts.IsProduction != nil {
		for _, t := range targets {
			if g.opts.IsProduction(t) {
				rec.ProductionTouching = true
				break
			}
		}
	}
	return rec
}

type userEvent struct {
	rec corroborate.Record
	ev  event
}

// sessions windows each authenticated user's activity. Binding
// precedence, strongest first:
//
//  1. impersonatedUser on the window's events → k8s-impersonation (the
//     cluster-enforced convention; the human is named per event).
//  2. A non-system, non-ServiceAccount username → actor-identity (an
//     OIDC/cert user authenticated as themselves).
//  3. Nothing: ServiceAccounts and system users without impersonation
//     stay unattributed — the gap the convention checker exists to name.
func (g *Ingester) sessions(byUser map[string][]userEvent) []corroborate.Session {
	var out []corroborate.Session
	for user, evs := range byUser {
		sort.Slice(evs, func(i, j int) bool { return evs[i].rec.RecordedAt.Before(evs[j].rec.RecordedAt) })
		start := 0
		for i := 1; i <= len(evs); i++ {
			if i < len(evs) && evs[i].rec.RecordedAt.Sub(evs[i-1].rec.RecordedAt) <= g.opts.SessionGap {
				continue
			}
			out = append(out, g.session(user, evs[start:i]))
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

func (g *Ingester) session(user string, window []userEvent) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	s := corroborate.Session{
		ID:          "k8s:" + g.opts.Cluster + "/" + user + "@" + first.rec.RecordedAt.UTC().Format(time.RFC3339),
		Agent:       user,
		StartedAt:   first.rec.RecordedAt,
		EndedAt:     last.rec.RecordedAt,
		Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
	}

	human := ""
	var evidence []string
	for _, ue := range window {
		if ue.rec.SourceIdentity == "" {
			continue
		}
		if human == "" {
			human = ue.rec.SourceIdentity
		}
		if ue.rec.SourceIdentity == human {
			evidence = append(evidence, ue.rec.ID)
		}
	}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrK8sImpersonation, Evidence: evidence}
		return s
	}

	if isHumanUsername(user) {
		evidence = make([]string, 0, len(window))
		for _, ue := range window {
			evidence = append(evidence, ue.rec.ID)
		}
		s.Human = user
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrActorIdentity, Evidence: evidence}
	}
	return s
}

// isHumanUsername separates authenticated people from machinery:
// ServiceAccounts and the control plane's system: identities are
// credentials, not humans.
func isHumanUsername(user string) bool {
	return user != "" && !strings.HasPrefix(user, "system:")
}

// splitEvents accepts what audit backends emit — the log backend's JSONL
// and the webhook backend's EventList (single- or multi-line) — by
// decoding a stream of JSON values, which subsumes both. EventList
// documents expand to their items. Returns each event's exact raw bytes
// for digesting. A malformed tail stops the stream (JSON gives no
// resync point) and is counted, not fatal.
func splitEvents(r io.Reader) (raws []json.RawMessage, badDocs int, err error) {
	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var doc json.RawMessage
		err := dec.Decode(&doc)
		if err == io.EOF {
			return raws, badDocs, nil
		}
		if err != nil {
			return raws, badDocs + 1, nil
		}
		doc = bytes.TrimSpace(doc)
		var probe struct {
			Kind  string            `json:"kind"`
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(doc, &probe) == nil && probe.Kind == "EventList" {
			raws = append(raws, probe.Items...)
			continue
		}
		raws = append(raws, doc)
	}
}
