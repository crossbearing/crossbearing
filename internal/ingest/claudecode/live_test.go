package claudecode

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestLive_IngestTranscript validates the ingester against a real Claude
// Code transcript — the shapes mocks can drift from: entry-type zoo,
// multi-hundred-KB result lines, real tool inventories.
//
// Skipped unless CROSSBEARING_TRANSCRIPT points at a transcript file:
//
//	CROSSBEARING_TRANSCRIPT=~/.claude/projects/<p>/<session>.jsonl \
//	  go test ./internal/ingest/claudecode -run TestLive -v
func TestLive_IngestTranscript(t *testing.T) {
	path := os.Getenv("CROSSBEARING_TRANSCRIPT")
	if path == "" {
		t.Skip("set CROSSBEARING_TRANSCRIPT to a transcript path to run")
	}

	g := New(nil, Options{DeclaredOperator: os.Getenv("CROSSBEARING_OPERATOR")})
	res, err := g.IngestFile(path)
	if err != nil {
		t.Fatalf("IngestFile: %v", err)
	}
	if len(res.Claims) == 0 {
		t.Fatal("no claims; expected a working session to have executed tools")
	}
	if len(res.Sessions) == 0 {
		t.Fatal("no sessions")
	}

	byOp := map[string]int{}
	var awsClaims int
	for _, c := range res.Claims {
		if c.ID == "" || c.Raw.Digest == "" || c.Raw.Locator == "" || c.ClaimedAt.IsZero() {
			t.Errorf("claim missing identity/provenance: %+v", c)
		}
		key := c.Operation
		if i := strings.IndexByte(key, '('); i > 0 {
			key = key[:i]
		}
		byOp[key]++
		if strings.HasPrefix(c.Target, "aws ") || strings.Contains(c.Target, " aws ") {
			awsClaims++
		}
	}

	for _, s := range res.Sessions {
		t.Logf("session %s agent=%s human=%q method=%s window=[%s → %s]",
			s.ID, s.Agent, s.Human, s.Attribution.Method,
			s.StartedAt.Format(time.RFC3339), s.EndedAt.Format(time.RFC3339))
	}
	t.Logf("claims: %d total, %d AWS-CLI-shaped (the record-corroborable ones)", len(res.Claims), awsClaims)
	for op, n := range byOp {
		t.Logf("  %-12s %d", op, n)
	}
}
