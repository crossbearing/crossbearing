package claudecode

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// DeclaredOperator names the human this transcript's sessions are
	// claimed to belong to. It is self-reported (the transcript itself
	// carries no identity), so sessions bind via AttrDeclared — the
	// weakest method; corroboration against record streams may upgrade it.
	// Empty leaves sessions unattributed.
	DeclaredOperator string

	// IncludeTool filters which tool calls become claims. Nil means all
	// of them — the ingester stays total and noise control belongs to the
	// match policy, same stance as the cloudtrail ingester.
	IncludeTool func(name string) bool
}

// Result is one transcript's output. A file normally holds one session,
// but the format doesn't promise that, so this doesn't either.
type Result struct {
	Sessions []corroborate.Session
	Claims   []corroborate.Claim
}

// Ingester parses Claude Code transcript JSONL into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Ingester{log: logger.With("component", "ingest-claudecode"), opts: opts}
}

// IngestFile ingests one transcript file; path becomes the provenance
// locator base, so keep it the path the file can be re-read at.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open transcript: %w", err)
	}
	defer f.Close()
	return g.Ingest(f, path)
}

// pendingClaim is a tool_use waiting for proof of execution (a
// tool_result referencing it).
type pendingClaim struct {
	claim corroborate.Claim
	order int
}

// Ingest reads transcript JSONL from r. locator names where this
// transcript can be re-read (normally its file path); it anchors every
// claim's provenance.
//
// Two passes folded into one read: tool_use blocks become pending claims,
// tool_result blocks mark them executed. Only executed claims are
// emitted — including errored ones, since a failed command still ran.
func (g *Ingester) Ingest(r io.Reader, locator string) (Result, error) {
	var (
		pending = make(map[string]pendingClaim) // tool_use ID → claim
		// tool_use ID → when its result arrived. The timestamp is not decoration:
		// it is the moment the agent's own stream PROVED the call executed, and
		// therefore the far end of the span in which the command could have run.
		// A script that sleeps 90s and waits on a rollout is not an instant, and
		// every command split out of it inherits the call's start time.
		executed = make(map[string]time.Time)    // tool_use ID → result time
		windows  = make(map[string][2]time.Time) // sessionId → [first, last] entry time
		order    int
		lineNo   int
		badLines int
	)

	// Transcript lines routinely exceed bufio.Scanner's default limits
	// (large tool results), so read with an unbounded line reader.
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		atEOF := err == io.EOF
		if err != nil && !atEOF {
			return Result{}, fmt.Errorf("failed to read transcript line %d: %w", lineNo+1, err)
		}
		// Digest the canonical line, not the terminator: otherwise the same
		// line hashes differently depending on whether it ends the file.
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(line) > 0 {
			lineNo++
			if !g.ingestLine(line, locator, &pending, executed, windows, &order) {
				badLines++
			}
		}
		if atEOF {
			break
		}
	}
	if badLines > 0 {
		g.log.Warn("skipped unparseable transcript lines", "locator", locator, "lines", badLines)
	}

	var res Result
	claims := make([]pendingClaim, 0, len(pending))
	for id, pc := range pending {
		at, ok := executed[id]
		if !ok {
			continue // no result: the call never ran, so it claims nothing
		}
		pc.claim.CompletedAt = at
		claims = append(claims, pc)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].order < claims[j].order })
	for _, pc := range claims {
		res.Claims = append(res.Claims, corroborate.ExpandShellClaim(pc.claim)...)
	}

	res.Sessions = g.sessions(windows, locator)
	g.log.Info("ingested claude-code transcript",
		"locator", locator, "lines", lineNo,
		"claims", len(res.Claims), "sessions", len(res.Sessions))
	return res, nil
}

// ingestLine folds one JSONL line into the accumulators; false means the
// line didn't parse.
func (g *Ingester) ingestLine(line []byte, locator string, pending *map[string]pendingClaim, executed map[string]time.Time, windows map[string][2]time.Time, order *int) bool {
	var e entry
	if err := json.Unmarshal(line, &e); err != nil {
		return false
	}
	if e.SessionID != "" {
		if at := e.time(); !at.IsZero() {
			w, ok := windows[e.SessionID]
			if !ok {
				w = [2]time.Time{at, at}
			}
			if at.Before(w[0]) {
				w[0] = at
			}
			if at.After(w[1]) {
				w[1] = at
			}
			windows[e.SessionID] = w
		}
	}

	switch e.Type {
	case "assistant":
		digest := ""
		for _, b := range e.blocks() {
			if b.Type != "tool_use" || b.ID == "" {
				continue
			}
			if g.opts.IncludeTool != nil && !g.opts.IncludeTool(b.Name) {
				continue
			}
			if digest == "" { // one digest per line, shared by its claims
				sum := sha256.Sum256(line)
				digest = hex.EncodeToString(sum[:])
			}
			op, target := operationAndTarget(b)
			(*pending)[b.ID] = pendingClaim{
				order: *order,
				claim: corroborate.Claim{
					ID:        b.ID,
					SessionID: e.SessionID,
					Source:    corroborate.SourceClaudeCodeTranscript,
					Operation: op,
					Target:    target,
					ClaimedAt: e.time(),
					Raw: corroborate.Provenance{
						Locator: "claude-code:" + locator + "#" + e.UUID + "/" + b.ID,
						Digest:  digest,
					},
				},
			}
			*order++
		}
	case "user":
		for _, b := range e.blocks() {
			if b.Type == "tool_result" && b.ToolUseID != "" {
				if _, seen := executed[b.ToolUseID]; !seen {
					executed[b.ToolUseID] = e.time()
				}
			}
		}
	}
	return true
}

// sessions builds one corroborate.Session per session ID seen, bound to
// the declared operator when one is configured.
func (g *Ingester) sessions(windows map[string][2]time.Time, locator string) []corroborate.Session {
	var out []corroborate.Session
	for id, w := range windows {
		s := corroborate.Session{
			ID:          id,
			Agent:       "claude-code",
			StartedAt:   w[0],
			EndedAt:     w[1],
			Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
		}
		if g.opts.DeclaredOperator != "" {
			s.Human = g.opts.DeclaredOperator
			s.Attribution = corroborate.Attribution{
				Method:   corroborate.AttrDeclared,
				Evidence: []string{"claude-code:" + locator},
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
