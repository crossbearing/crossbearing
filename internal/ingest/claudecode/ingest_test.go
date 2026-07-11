package claudecode

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

const (
	sessionID = "f0b7fa2e-26e4-4fa7-ad56-66c4c66623f0"
	locator   = "/home/operator/.claude/projects/-p/f0b7fa2e.jsonl"
)

// assistantLine fabricates an assistant transcript entry carrying one
// tool_use block, shaped like the real format (version 2.x).
func assistantLine(uuid, ts, toolID, toolName, inputJSON string) string {
	return fmt.Sprintf(`{"type":"assistant","sessionId":%q,"uuid":%q,"timestamp":%q,"userType":"external","version":"2.1.170","cwd":"/home/operator/codes/x","message":{"role":"assistant","content":[{"type":"tool_use","id":%q,"name":%q,"input":%s}]}}`,
		sessionID, uuid, ts, toolID, toolName, inputJSON)
}

// resultLine fabricates the user entry acknowledging a tool_use ran.
func resultLine(uuid, ts, toolUseID string, isError bool) string {
	return fmt.Sprintf(`{"type":"user","sessionId":%q,"uuid":%q,"timestamp":%q,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":%q,"is_error":%v,"content":"ok"}]}}`,
		sessionID, uuid, ts, toolUseID, isError)
}

func ingest(t *testing.T, opts Options, lines ...string) Result {
	t.Helper()
	res, err := New(nil, opts).Ingest(strings.NewReader(strings.Join(lines, "\n")+"\n"), locator)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	return res
}

func TestIngest_ExecutedBashClaim(t *testing.T) {
	t.Parallel()
	use := assistantLine("uuid-1", "2026-06-10T02:55:44.067Z", "toolu_01A", "Bash",
		`{"command":"aws sts get-caller-identity --profile stxkxs","description":"check identity"}`)
	res := ingest(t, Options{},
		use,
		resultLine("uuid-2", "2026-06-10T02:55:48.306Z", "toolu_01A", false),
	)

	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(res.Claims))
	}
	c := res.Claims[0]
	if c.ID != "toolu_01A" {
		t.Errorf("ID = %q, want toolu_01A", c.ID)
	}
	if c.SessionID != sessionID {
		t.Errorf("SessionID = %q, want %q", c.SessionID, sessionID)
	}
	if c.Source != corroborate.SourceClaudeCodeTranscript {
		t.Errorf("Source = %q, want %q", c.Source, corroborate.SourceClaudeCodeTranscript)
	}
	if want := "Bash(aws sts get-caller-identity --profile stxkxs)"; c.Operation != want {
		t.Errorf("Operation = %q, want %q", c.Operation, want)
	}
	if want := "aws sts get-caller-identity --profile stxkxs"; c.Target != want {
		t.Errorf("Target = %q, want %q", c.Target, want)
	}
	if want := time.Date(2026, 6, 10, 2, 55, 44, 67_000_000, time.UTC); !c.ClaimedAt.Equal(want) {
		t.Errorf("ClaimedAt = %v, want %v", c.ClaimedAt, want)
	}
	if want := "claude-code:" + locator + "#uuid-1/toolu_01A"; c.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", c.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(use))
	if want := hex.EncodeToString(sum[:]); c.Raw.Digest != want {
		t.Errorf("Digest = %q, want sha256 of the raw line as ingested", c.Raw.Digest)
	}
}

func TestIngest_UnexecutedToolUseIsNotAClaim(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Bash", `{"command":"rm -rf /tmp/x"}`),
		// no tool_result: interrupted or denied — the agent never did it
	)
	if len(res.Claims) != 0 {
		t.Fatalf("claims = %d, want 0 for a tool_use with no result", len(res.Claims))
	}
}

func TestIngest_ErroredResultStillClaims(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Bash", `{"command":"aws s3 rm s3://prod-bucket/k"}`),
		resultLine("uuid-2", "2026-06-10T02:55:48Z", "toolu_01A", true),
	)
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1: a failed command still executed", len(res.Claims))
	}
}

func TestIngest_OperationVocabulary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tool, input, wantOp, wantTarget string
	}{
		{"Write", `{"file_path":"/repo/main.go","content":"..."}`, "Write", "/repo/main.go"},
		{"Edit", `{"file_path":"/repo/a.go","old_string":"x","new_string":"y"}`, "Edit", "/repo/a.go"},
		{"mcp__github__create_pull_request", `{"title":"t"}`, "mcp:github:create_pull_request", ""},
		{"WebFetch", `{"url":"https://example.com"}`, "WebFetch", "https://example.com"},
		{"Glob", `{"pattern":"**/*.go"}`, "Glob", "**/*.go"},
		{"Skill", `{"skill":"commit"}`, "Skill", "commit"},
	}
	for i, tt := range tests {
		toolID := fmt.Sprintf("toolu_%02d", i)
		res := ingest(t, Options{},
			assistantLine("uuid-1", "2026-06-10T02:55:44Z", toolID, tt.tool, tt.input),
			resultLine("uuid-2", "2026-06-10T02:55:48Z", toolID, false),
		)
		if len(res.Claims) != 1 {
			t.Fatalf("%s: claims = %d, want 1", tt.tool, len(res.Claims))
		}
		if res.Claims[0].Operation != tt.wantOp {
			t.Errorf("%s: Operation = %q, want %q", tt.tool, res.Claims[0].Operation, tt.wantOp)
		}
		if res.Claims[0].Target != tt.wantTarget {
			t.Errorf("%s: Target = %q, want %q", tt.tool, res.Claims[0].Target, tt.wantTarget)
		}
	}
}

func TestIngest_BashOperationTruncatesButTargetKeepsAll(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 150)
	cmd := "git commit -m \"first\"\n" + long
	inputJSON := fmt.Sprintf(`{"command":%q}`, cmd)
	res := ingest(t, Options{},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Bash", inputJSON),
		resultLine("uuid-2", "2026-06-10T02:55:48Z", "toolu_01A", false),
	)
	c := res.Claims[0]
	if want := `Bash(git commit -m "first")`; c.Operation != want {
		t.Errorf("Operation = %q, want first line only: %q", c.Operation, want)
	}
	if c.Target != cmd {
		t.Errorf("Target lost content: %d bytes, want %d", len(c.Target), len(cmd))
	}

	res = ingest(t, Options{},
		assistantLine("uuid-3", "2026-06-10T02:56:44Z", "toolu_01B", "Bash", fmt.Sprintf(`{"command":%q}`, long)),
		resultLine("uuid-4", "2026-06-10T02:56:48Z", "toolu_01B", false),
	)
	if op := res.Claims[0].Operation; len(op) > len("Bash()")+110 {
		t.Errorf("Operation not truncated: %d bytes", len(op))
	}
}

func TestIngest_IncludeToolFilter(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{IncludeTool: func(name string) bool { return name == "Write" }},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Read", `{"file_path":"/a"}`),
		resultLine("uuid-2", "2026-06-10T02:55:45Z", "toolu_01A", false),
		assistantLine("uuid-3", "2026-06-10T02:55:46Z", "toolu_01B", "Write", `{"file_path":"/b"}`),
		resultLine("uuid-4", "2026-06-10T02:55:47Z", "toolu_01B", false),
	)
	if len(res.Claims) != 1 || res.Claims[0].Operation != "Write" {
		t.Fatalf("claims = %+v, want only the Write claim", res.Claims)
	}
}

func TestIngest_MultipleToolUsesOneLine(t *testing.T) {
	t.Parallel()
	line := fmt.Sprintf(`{"type":"assistant","sessionId":%q,"uuid":"uuid-1","timestamp":"2026-06-10T02:55:44Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01A","name":"Read","input":{"file_path":"/a"}},{"type":"tool_use","id":"toolu_01B","name":"Read","input":{"file_path":"/b"}}]}}`, sessionID)
	res := ingest(t, Options{},
		line,
		resultLine("uuid-2", "2026-06-10T02:55:45Z", "toolu_01A", false),
		resultLine("uuid-3", "2026-06-10T02:55:45Z", "toolu_01B", false),
	)
	if len(res.Claims) != 2 {
		t.Fatalf("claims = %d, want 2 from one line", len(res.Claims))
	}
	if res.Claims[0].Raw.Digest != res.Claims[1].Raw.Digest {
		t.Error("claims from one line must share the line digest")
	}
	if res.Claims[0].Raw.Locator == res.Claims[1].Raw.Locator {
		t.Error("claims from one line must have distinct locators")
	}
	if res.Claims[0].Target != "/a" || res.Claims[1].Target != "/b" {
		t.Errorf("claim order not preserved: %q, %q", res.Claims[0].Target, res.Claims[1].Target)
	}
}

func TestIngest_TextContentAndMetadataLinesIgnored(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		`{"type":"user","sessionId":"`+sessionID+`","uuid":"u1","timestamp":"2026-06-10T02:55:40Z","message":{"role":"user","content":"rip it"}}`,
		`{"type":"file-history-snapshot","messageId":"m1"}`,
		`{"type":"system","sessionId":"`+sessionID+`","uuid":"u2","timestamp":"2026-06-10T02:55:41Z"}`,
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Write", `{"file_path":"/a"}`),
		resultLine("uuid-2", "2026-06-10T02:55:48Z", "toolu_01A", false),
	)
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(res.Claims))
	}
}

func TestIngest_MalformedLineSkippedRestIngested(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		`{"type":"assistant", not json`,
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Write", `{"file_path":"/a"}`),
		resultLine("uuid-2", "2026-06-10T02:55:48Z", "toolu_01A", false),
	)
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1 despite a malformed line", len(res.Claims))
	}
}

func TestIngest_HugeLine(t *testing.T) {
	t.Parallel()
	// Real transcripts carry tool results far beyond bufio.Scanner's 64KB
	// default; the reader must not choke.
	big := strings.Repeat("y", 300*1024)
	res := ingest(t, Options{},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Write", `{"file_path":"/a"}`),
		fmt.Sprintf(`{"type":"user","sessionId":%q,"uuid":"uuid-2","timestamp":"2026-06-10T02:55:48Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01A","content":%q}]}}`, sessionID, big),
	)
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1 with a 300KB result line", len(res.Claims))
	}
}

func TestIngest_SessionWindowAndDeclaredOperator(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{DeclaredOperator: "bs@example.com"},
		`{"type":"user","sessionId":"`+sessionID+`","uuid":"u1","timestamp":"2026-06-10T02:50:00Z","message":{"role":"user","content":"go"}}`,
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Write", `{"file_path":"/a"}`),
		resultLine("uuid-2", "2026-06-10T03:10:00Z", "toolu_01A", false),
	)

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.ID != sessionID {
		t.Errorf("ID = %q, want %q", s.ID, sessionID)
	}
	if s.Agent != "claude-code" {
		t.Errorf("Agent = %q, want claude-code", s.Agent)
	}
	if !s.StartedAt.Equal(time.Date(2026, 6, 10, 2, 50, 0, 0, time.UTC)) {
		t.Errorf("StartedAt = %v, want first entry time", s.StartedAt)
	}
	if !s.EndedAt.Equal(time.Date(2026, 6, 10, 3, 10, 0, 0, time.UTC)) {
		t.Errorf("EndedAt = %v, want last entry time", s.EndedAt)
	}
	if s.Human != "bs@example.com" {
		t.Errorf("Human = %q, want declared operator", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrDeclared {
		t.Errorf("Method = %q, want %q (self-reported is the weakest binding)", s.Attribution.Method, corroborate.AttrDeclared)
	}
	if len(s.Attribution.Evidence) != 1 || s.Attribution.Evidence[0] != "claude-code:"+locator {
		t.Errorf("Evidence = %v, want the transcript locator", s.Attribution.Evidence)
	}
}

func TestIngest_NoDeclaredOperatorMeansUnattributed(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		assistantLine("uuid-1", "2026-06-10T02:55:44Z", "toolu_01A", "Write", `{"file_path":"/a"}`),
		resultLine("uuid-2", "2026-06-10T02:55:48Z", "toolu_01A", false),
	)
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("got Human=%q Method=%q, want unattributed", s.Human, s.Attribution.Method)
	}
}

func TestIngest_EmptyInput(t *testing.T) {
	t.Parallel()
	res, err := New(nil, Options{}).Ingest(strings.NewReader(""), locator)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if len(res.Claims) != 0 || len(res.Sessions) != 0 {
		t.Fatalf("got %d claims, %d sessions from empty input", len(res.Claims), len(res.Sessions))
	}
}
