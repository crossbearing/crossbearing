package bedrock

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestLive_Ingest validates the ingester against a real Bedrock
// model-invocation log — the byte shapes documentation cannot prove:
// whether inputBodyJson/outputBodyJson arrive as objects or stringified,
// the Converse toolUse/toolResult member spelling, the native-Anthropic
// content blocks, MCP tool names arriving as mcp__server__tool, and the
// identity.arn the session keys on.
//
// Skipped unless CROSSBEARING_BEDROCK_LOG points at a captured log (JSONL
// of ModelInvocationLog records, gz or plain — e.g. the concatenated
// objects Bedrock delivers to the S3 logging destination).
//
//	CROSSBEARING_BEDROCK_LOG=<capture.jsonl> go test ./internal/ingest/bedrock -run TestLive -v
func TestLive_Ingest(t *testing.T) {
	path := os.Getenv("CROSSBEARING_BEDROCK_LOG")
	if path == "" {
		t.Skip("set CROSSBEARING_BEDROCK_LOG to a captured invocation log to run")
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer f.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	res, err := New(logger, Options{}).Ingest(f, "bedrock-live:"+path)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	t.Logf("claims=%d sessions=%d", len(res.Claims), len(res.Sessions))
	if len(res.Claims) == 0 {
		t.Fatal("no claims extracted from a real capture — executed tool calls should claim")
	}
	if len(res.Sessions) == 0 {
		t.Fatal("no sessions derived from a real capture")
	}

	// The live gate's specific questions, asserted against whatever the
	// capture carries: every claim must have provenance and a session; a
	// shell-shaped tool must arrive in Bash(...) claim vocabulary; an MCP
	// tool name must arrive normalized to mcp:server:tool.
	var sawBash, sawMCP bool
	for _, c := range res.Claims {
		t.Logf("claim: %s at %s (session %s)", c.Operation, c.ClaimedAt, c.SessionID)
		if c.Raw.Digest == "" || c.Raw.Locator == "" {
			t.Errorf("claim %s missing provenance", c.ID)
		}
		if strings.HasPrefix(c.Operation, "Bash(") {
			sawBash = true
		}
		if strings.HasPrefix(c.Operation, "mcp:") {
			sawMCP = true
		}
	}
	if !sawBash {
		t.Error("capture contains a Bash-shaped toolUse but no Bash(...) claim was extracted")
	}
	if !sawMCP {
		t.Error("capture contains an mcp__server__tool toolUse but no mcp:... claim was extracted")
	}
	for _, s := range res.Sessions {
		t.Logf("session: %s agent=%s human=%q (%s)", s.ID, s.Agent, s.Human, s.Attribution.Method)
		if s.Agent == "" {
			t.Errorf("session %s has no agent", s.ID)
		}
	}
}
