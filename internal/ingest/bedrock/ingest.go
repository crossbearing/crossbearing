package bedrock

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/ingest"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// DeclaredOperator names the human these sessions are claimed to belong
	// to. Bedrock invocation logs carry only the calling role ARN, not a
	// human, so sessions bind via AttrDeclared — the weakest method;
	// corroboration against record streams may upgrade it. Empty leaves
	// sessions unattributed.
	DeclaredOperator string

	// Agent labels the acting tool on each session (e.g. "kagent"). Empty
	// defaults to "bedrock".
	Agent string

	// SessionKey selects a requestMetadata entry to group invocations into
	// sessions (e.g. the kagent session id the client stamped). When it is
	// empty, or absent on a record, the calling role ARN groups the session
	// instead — the coarsest grouping, and the reason per-agent attribution
	// wants a session tag.
	SessionKey string

	// IncludeTool filters which tool calls become claims. Nil means all of
	// them — the ingester stays total and noise control belongs to the match
	// policy, the same stance as the cloudtrail and claudecode ingesters.
	IncludeTool func(name string) bool
}

// Result is one log's output.
type Result struct {
	Sessions []corroborate.Session
	Claims   []corroborate.Claim
}

// Ingester parses Bedrock model-invocation-log JSON into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.Agent == "" {
		opts.Agent = "bedrock"
	}
	return &Ingester{log: logger.With("component", "ingest-bedrock"), opts: opts}
}

// IngestFile ingests one invocation-log file; path becomes the provenance
// locator base, so keep it the path the file can be re-read at. Gzip is
// detected from the content, so an S3 *.json.gz export works directly.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open bedrock invocation log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f, path)
}

// pendingClaim is a tool_use waiting for proof of execution (a tool_result
// referencing it, which the agent submits in a following invocation).
type pendingClaim struct {
	claim corroborate.Claim
	order int
}

// Ingest reads invocation-log records from r in either export shape (a JSON
// array or newline-delimited records), transparently decompressing gzip.
// locator names where this log can be re-read; it anchors every claim's
// provenance.
//
// Two passes folded into one read: toolUse blocks become pending claims,
// toolResult blocks (carried in a later record's request body) mark them
// executed. Only executed claims are emitted — including errored ones, since
// a failed tool still ran.
func (g *Ingester) Ingest(r io.Reader, locator string) (Result, error) {
	dec, closer, err := maybeGunzip(r)
	if err != nil {
		return Result{}, fmt.Errorf("failed to read bedrock invocation log: %w", err)
	}
	raws, badEntries, err := ingest.SplitJSONArrayOrLines(dec)
	if closer != nil {
		// Closing the gzip reader validates the trailing CRC/length, so a
		// truncated-but-parseable export surfaces as an error rather than a
		// silent short read.
		if cerr := closer.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("gzip integrity check failed: %w", cerr)
		}
	}
	if err != nil {
		return Result{}, err
	}
	if badEntries > 0 {
		g.log.Warn("skipped unparseable bedrock invocation entries", "locator", locator, "entries", badEntries)
	}

	var (
		pending  = make(map[string]pendingClaim) // tool_use ID → claim
		executed = make(map[string]bool)         // tool_use IDs with results
		windows  = make(map[string][2]time.Time) // sessionID → [first, last]
		order    int
		skipped  int
	)
	for _, raw := range raws {
		var l invocationLog
		if json.Unmarshal(raw, &l) != nil {
			skipped++
			continue
		}
		sid := g.sessionID(&l)
		if sid != "" {
			// Seed a window for every session id seen — even one whose records
			// all lack a parseable timestamp — so an executed claim always has
			// a Session to join through (Join looks claims up by their session;
			// a claim with no session would be silently dropped).
			w, ok := windows[sid]
			if !ok {
				w = [2]time.Time{}
			}
			if !l.Timestamp.IsZero() {
				if w[0].IsZero() || l.Timestamp.Before(w[0]) {
					w[0] = l.Timestamp
				}
				if l.Timestamp.After(w[1]) {
					w[1] = l.Timestamp
				}
			}
			windows[sid] = w
		}

		uses, results := l.toolActivity()
		for _, id := range results {
			executed[id] = true
		}
		digest := "" // one digest per record, shared by its claims
		for _, tc := range uses {
			if tc.ID == "" {
				continue
			}
			if _, seen := pending[tc.ID]; seen {
				continue // first occurrence wins (provenance points at the earliest record)
			}
			if g.opts.IncludeTool != nil && !g.opts.IncludeTool(tc.Name) {
				continue
			}
			if digest == "" {
				digest = corroborate.DigestHex(raw)
			}
			op, target := operationAndTarget(tc)
			pending[tc.ID] = pendingClaim{
				order: order,
				claim: corroborate.Claim{
					ID:        tc.ID,
					SessionID: sid,
					Source:    corroborate.SourceBedrockInvocation,
					Operation: op,
					Target:    target,
					ClaimedAt: l.Timestamp,
					Raw: corroborate.Provenance{
						Locator: "bedrock:" + locator + "#" + l.RequestID + "/" + tc.ID,
						Digest:  digest,
					},
				},
			}
			order++
		}
	}
	if skipped > 0 {
		g.log.Warn("skipped undecodable bedrock invocation entries", "locator", locator, "entries", skipped)
	}

	var res Result
	claims := make([]pendingClaim, 0, len(pending))
	for id, pc := range pending {
		if executed[id] {
			claims = append(claims, pc)
		}
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].order < claims[j].order })
	for _, pc := range claims {
		res.Claims = append(res.Claims, pc.claim)
	}

	res.Sessions = g.sessions(windows, locator)
	g.log.Info("ingested bedrock invocation log",
		"locator", locator, "records", len(raws),
		"claims", len(res.Claims), "sessions", len(res.Sessions))
	return res, nil
}

// sessionID groups a record into a session: the configured requestMetadata
// key when present, else the calling role ARN.
func (g *Ingester) sessionID(l *invocationLog) string {
	if g.opts.SessionKey != "" {
		if v := l.RequestMetadata[g.opts.SessionKey]; v != "" {
			return v
		}
	}
	return l.Identity.ARN
}

// sessions builds one corroborate.Session per session ID seen, bound to the
// declared operator when one is configured.
func (g *Ingester) sessions(windows map[string][2]time.Time, locator string) []corroborate.Session {
	var out []corroborate.Session
	for id, w := range windows {
		s := corroborate.Session{
			ID:          id,
			Agent:       g.opts.Agent,
			StartedAt:   w[0],
			EndedAt:     w[1],
			Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
		}
		if g.opts.DeclaredOperator != "" {
			s.Human = g.opts.DeclaredOperator
			s.Attribution = corroborate.Attribution{
				Method:   corroborate.AttrDeclared,
				Evidence: []string{"bedrock:" + locator},
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// maybeGunzip wraps r in a gzip reader when the stream begins with the gzip
// magic bytes, so an S3 *.json.gz invocation-log export is read directly.
// Uses stdlib compress/gzip — zero new dependencies. The returned Closer is
// the gzip reader when one was used (nil otherwise); closing it validates the
// trailing CRC so a truncated body is caught, and the caller is responsible
// for it.
func maybeGunzip(r io.Reader) (io.Reader, io.Closer, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		return gz, gz, nil
	}
	return br, nil, nil
}
