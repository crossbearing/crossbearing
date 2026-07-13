package bedrock

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// A Converse turn pair: record req-1's response carries the model's toolUse
// (a shell tool running kubectl); record req-2's request carries the
// toolResult that proves it executed. Both records share one kagent session.
const conversePair = `[
 {
  "schemaType":"ModelInvocationLog","schemaVersion":"1.0",
  "timestamp":"2026-06-11T10:00:00Z","accountId":"111122223333","region":"us-west-2",
  "requestId":"req-1","operation":"Converse","modelId":"anthropic.claude-sonnet-4",
  "identity":{"arn":"arn:aws:sts::111122223333:assumed-role/kagent-agent/sess-1"},
  "requestMetadata":{"session":"kagent-abc"},
  "input":{"inputBodyJson":{"messages":[{"role":"user","content":[{"text":"scale checkout"}]}]}},
  "output":{"outputBodyJson":{"output":{"message":{"role":"assistant","content":[
     {"toolUse":{"toolUseId":"tu-1","name":"shell","input":{"command":"kubectl -n payments scale deploy/checkout --replicas=4"}}}
  ]}},"stopReason":"tool_use"}}
 },
 {
  "schemaType":"ModelInvocationLog","schemaVersion":"1.0",
  "timestamp":"2026-06-11T10:00:05Z","accountId":"111122223333","region":"us-west-2",
  "requestId":"req-2","operation":"Converse","modelId":"anthropic.claude-sonnet-4",
  "identity":{"arn":"arn:aws:sts::111122223333:assumed-role/kagent-agent/sess-1"},
  "requestMetadata":{"session":"kagent-abc"},
  "input":{"inputBodyJson":{"messages":[
     {"role":"user","content":[{"text":"scale checkout"}]},
     {"role":"assistant","content":[{"toolUse":{"toolUseId":"tu-1","name":"shell","input":{"command":"kubectl -n payments scale deploy/checkout --replicas=4"}}}]},
     {"role":"user","content":[{"toolResult":{"toolUseId":"tu-1","status":"success","content":[{"text":"deployment.apps/checkout scaled"}]}}]}
  ]}},
  "output":{"outputBodyJson":{"output":{"message":{"content":[{"text":"done"}]}},"stopReason":"end_turn"}}
 }
]`

func ingestString(t *testing.T, s string, opts Options) Result {
	t.Helper()
	res, err := New(nil, opts).Ingest(strings.NewReader(s), "log.json")
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return res
}

func TestIngest_ConverseExecutedClaim(t *testing.T) {
	res := ingestString(t, conversePair, Options{SessionKey: "session", DeclaredOperator: "alice@acme.com"})

	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1: %+v", len(res.Claims), res.Claims)
	}
	c := res.Claims[0]
	if c.ID != "tu-1" {
		t.Errorf("claim ID = %q, want tu-1", c.ID)
	}
	if c.Source != corroborate.SourceBedrockInvocation {
		t.Errorf("source = %q, want %q", c.Source, corroborate.SourceBedrockInvocation)
	}
	if c.SessionID != "kagent-abc" {
		t.Errorf("sessionID = %q, want kagent-abc", c.SessionID)
	}
	if want := "Bash(kubectl -n payments scale deploy/checkout --replicas=4)"; c.Operation != want {
		t.Errorf("operation = %q, want %q", c.Operation, want)
	}
	if want := "kubectl -n payments scale deploy/checkout --replicas=4"; c.Target != want {
		t.Errorf("target = %q, want %q", c.Target, want)
	}
	// Provenance points at the earliest record carrying the tool_use (req-1).
	if !strings.HasPrefix(c.Raw.Locator, "bedrock:log.json#req-1/tu-1") {
		t.Errorf("locator = %q, want bedrock:log.json#req-1/tu-1", c.Raw.Locator)
	}
	if len(c.Raw.Digest) != 64 {
		t.Errorf("digest = %q, want 64-hex", c.Raw.Digest)
	}

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.ID != "kagent-abc" || s.Agent != "bedrock" {
		t.Errorf("session = {ID:%q Agent:%q}, want {kagent-abc bedrock}", s.ID, s.Agent)
	}
	if s.Human != "alice@acme.com" || s.Attribution.Method != corroborate.AttrDeclared {
		t.Errorf("attribution = {%q %q}, want {alice@acme.com declared}", s.Human, s.Attribution.Method)
	}
	if s.StartedAt.IsZero() || !s.EndedAt.After(s.StartedAt) {
		t.Errorf("window = [%s,%s], want started<ended", s.StartedAt, s.EndedAt)
	}
}

// The Operation derived from the claim is the same string the kubectl
// translator and the k8s record side meet on, so the join corroborates.
func TestIngest_DerivedOperationMeetsK8sRecord(t *testing.T) {
	res := ingestString(t, conversePair, Options{SessionKey: "session"})
	m := corroborate.DeriveOperationMap(res.Claims)
	ops := m[corroborate.ClaimKey(res.Claims[0])]
	want := "k8s-audit:update:deployments/scale"
	found := false
	for _, o := range ops {
		if o == want {
			found = true
		}
	}
	if !found {
		t.Errorf("derived ops %v do not include %q (claim<->record would not join)", ops, want)
	}
}

func TestIngest_NativeAnthropicShape(t *testing.T) {
	const native = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"InvokeModel","modelId":"anthropic.claude-3","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":{"stop_reason":"tool_use","content":[
     {"type":"text","text":"ok"},
     {"type":"tool_use","id":"toolu_9","name":"k8s_apply","input":{"manifest":"kind: ConfigMap"}}
  ]}}},
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:03Z","requestId":"r2",
  "operation":"InvokeModel","modelId":"anthropic.claude-3","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "input":{"inputBodyJson":{"messages":[
     {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_9","is_error":false,"content":"applied"}]}
  ]}}}
]`
	res := ingestString(t, native, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(res.Claims))
	}
	c := res.Claims[0]
	if c.ID != "toolu_9" || c.Operation != "k8s_apply" || c.Target != "kind: ConfigMap" {
		t.Errorf("claim = {ID:%q Op:%q Target:%q}, want {toolu_9 k8s_apply 'kind: ConfigMap'}", c.ID, c.Operation, c.Target)
	}
	// No session key configured → grouped by the calling role ARN.
	if c.SessionID != "arn:aws:sts::1:assumed-role/a/s" {
		t.Errorf("sessionID = %q, want the role ARN", c.SessionID)
	}
}

func TestIngest_StringContentTurnDoesNotPoisonBody(t *testing.T) {
	// The Anthropic API accepts message content as a plain string OR an
	// array of blocks, and real requests mix them — the first user turn is
	// commonly a string. Live validation (2026-07-09, real invocation log)
	// caught the strict array-only decode failing the WHOLE body on the
	// string turn, hiding the tool_result carried by a sibling turn — the
	// executed tool call produced no claim. This is that capture's shape,
	// sanitized.
	const mixed = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"InvokeModel","modelId":"anthropic.claude-3","identity":{"arn":"arn:aws:sts::111122223333:assumed-role/a/s"},
  "output":{"outputBodyJson":{"stop_reason":"tool_use","content":[
     {"type":"tool_use","id":"toolu_1","name":"mcp__github__create_branch","input":{"repo":"acme/prod-web","branch":"release/1"}}
  ]}}},
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:31Z","requestId":"r2",
  "operation":"InvokeModel","modelId":"anthropic.claude-3","identity":{"arn":"arn:aws:sts::111122223333:assumed-role/a/s"},
  "input":{"inputBodyJson":{"messages":[
     {"role":"user","content":"Use the tool to create the branch."},
     {"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"mcp__github__create_branch","input":{"repo":"acme/prod-web","branch":"release/1"}}]},
     {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"branch created"}]}
  ]}}}
]`
	res := ingestString(t, mixed, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1 (string-content turn must not hide the tool_result)", len(res.Claims))
	}
	if got := res.Claims[0].Operation; got != "mcp:github:create_branch" {
		t.Errorf("operation = %q, want the normalized mcp:github:create_branch", got)
	}
}

func TestIngest_UnexecutedToolUseDropped(t *testing.T) {
	// A toolUse the model emitted but whose result was never submitted: the
	// agent never actually ran it, so it is not a claim.
	const proposedOnly = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"Converse","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":{"output":{"message":{"content":[
     {"toolUse":{"toolUseId":"tu-x","name":"shell","input":{"command":"kubectl delete ns prod"}}}
  ]}},"stopReason":"tool_use"}}}
]`
	res := ingestString(t, proposedOnly, Options{})
	if len(res.Claims) != 0 {
		t.Fatalf("claims = %d, want 0 (no result = never ran)", len(res.Claims))
	}
	// The session window is still recorded so the join can scope its records.
	if len(res.Sessions) != 1 {
		t.Errorf("sessions = %d, want 1", len(res.Sessions))
	}
}

func TestIngest_ErroredResultStillCounts(t *testing.T) {
	// A tool that failed still executed (it may have touched infra before
	// failing), so an errored toolResult still proves the claim.
	const errored = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"Converse","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":{"output":{"message":{"content":[
     {"toolUse":{"toolUseId":"tu-e","name":"shell","input":{"command":"kubectl get pods"}}}
  ]}},"stopReason":"tool_use"}}},
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:01Z","requestId":"r2",
  "operation":"Converse","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "input":{"inputBodyJson":{"messages":[{"role":"user","content":[
     {"toolResult":{"toolUseId":"tu-e","status":"error","content":[{"text":"forbidden"}]}}
  ]}]}}}
]`
	res := ingestString(t, errored, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1 (errored still counts)", len(res.Claims))
	}
}

func TestIngest_GzipAndJSONL(t *testing.T) {
	// One record, expressed as a single JSONL line so we control its exact
	// bytes and can assert the provenance digest is the SHA-256 of them.
	line := `{"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1","operation":"Converse","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},"input":{"inputBodyJson":{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"tu-1","status":"success"}}]}]}},"output":{"outputBodyJson":{"output":{"message":{"content":[{"toolUse":{"toolUseId":"tu-1","name":"shell","input":{"command":"aws s3 ls"}}}]}},"stopReason":"tool_use"}}}`

	res := ingestString(t, line+"\n", Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("jsonl: claims = %d, want 1", len(res.Claims))
	}
	if want := corroborate.DigestHex([]byte(line)); res.Claims[0].Raw.Digest != want {
		t.Errorf("jsonl digest = %q, want DigestHex(line) %q", res.Claims[0].Raw.Digest, want)
	}

	// Same content, gzipped — the magic-byte sniff must transparently inflate.
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte("[" + line + "]")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	gres, err := New(nil, Options{}).Ingest(&gz, "log.json.gz")
	if err != nil {
		t.Fatalf("gzip Ingest: %v", err)
	}
	if len(gres.Claims) != 1 {
		t.Fatalf("gzip: claims = %d, want 1", len(gres.Claims))
	}
}

func TestIngest_EmptyAndGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\n", "not json\nalso not json"} {
		res, err := New(nil, Options{}).Ingest(strings.NewReader(in), "x")
		if err != nil {
			t.Errorf("Ingest(%q) errored: %v", in, err)
		}
		if len(res.Claims) != 0 || len(res.Sessions) != 0 {
			t.Errorf("Ingest(%q) = %d claims / %d sessions, want 0/0", in, len(res.Claims), len(res.Sessions))
		}
	}
}

func TestIngest_StringifiedBody(t *testing.T) {
	// Some CloudWatch exports stringify the body JSON; both halves stringified.
	const stringified = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"Converse","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":"{\"output\":{\"message\":{\"content\":[{\"toolUse\":{\"toolUseId\":\"tu-1\",\"name\":\"shell\",\"input\":{\"command\":\"kubectl get pods\"}}}]}}}"},
  "input":{"inputBodyJson":"{\"messages\":[{\"role\":\"user\",\"content\":[{\"toolResult\":{\"toolUseId\":\"tu-1\",\"status\":\"success\"}}]}]}"}}
]`
	res := ingestString(t, stringified, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("stringified body: claims = %d, want 1", len(res.Claims))
	}
	if res.Claims[0].Operation != "Bash(kubectl get pods)" {
		t.Errorf("operation = %q, want Bash(kubectl get pods)", res.Claims[0].Operation)
	}
}

func TestIngest_McpToolNameNormalized(t *testing.T) {
	// An MCP tool call (named mcp__<server>__<tool> by the runtime) is
	// normalized to the mcp:<server>:<tool> claim vocabulary so the attested
	// github seed map corroborates it against the org audit log.
	const mcp = `[
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:00Z","requestId":"r1",
  "operation":"InvokeModel","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":{"stop_reason":"tool_use","content":[
     {"type":"tool_use","id":"toolu_1","name":"mcp__github__merge_pull_request","input":{"pullNumber":7}}
  ]}}},
 {"schemaType":"ModelInvocationLog","timestamp":"2026-06-11T10:00:02Z","requestId":"r2",
  "operation":"InvokeModel","modelId":"m","identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "input":{"inputBodyJson":{"messages":[{"role":"user","content":[
     {"type":"tool_result","tool_use_id":"toolu_1","content":"merged"}
  ]}]}}}
]`
	res := ingestString(t, mcp, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(res.Claims))
	}
	if got := res.Claims[0].Operation; got != "mcp:github:merge_pull_request" {
		t.Fatalf("operation = %q, want mcp:github:merge_pull_request", got)
	}
	// the normalized op is wired to github-audit by the attested seed → it joins.
	if _, ok := corroborate.MCPGitHubOperationMap()["mcp:github:merge_pull_request"]; !ok {
		t.Error("normalized op absent from MCPGitHubOperationMap seed — would not corroborate")
	}
}

func TestIngest_TimelessRecordsStillYieldSession(t *testing.T) {
	// Records with no parseable timestamp must still produce a Session, or
	// the executed claim they carry would reference a session that does not
	// exist and be silently dropped by the join.
	const timeless = `[
 {"schemaType":"ModelInvocationLog","requestId":"r1","operation":"Converse","modelId":"m",
  "identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "output":{"outputBodyJson":{"output":{"message":{"content":[
     {"toolUse":{"toolUseId":"tu-1","name":"shell","input":{"command":"kubectl get pods"}}}
  ]}},"stopReason":"tool_use"}}},
 {"schemaType":"ModelInvocationLog","requestId":"r2","operation":"Converse","modelId":"m",
  "identity":{"arn":"arn:aws:sts::1:assumed-role/a/s"},
  "input":{"inputBodyJson":{"messages":[{"role":"user","content":[
     {"toolResult":{"toolUseId":"tu-1","status":"success"}}
  ]}]}}}
]`
	res := ingestString(t, timeless, Options{})
	if len(res.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(res.Claims))
	}
	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1 (timeless records must still seed a session)", len(res.Sessions))
	}
	if res.Sessions[0].ID != res.Claims[0].SessionID {
		t.Errorf("session ID %q != claim SessionID %q (claim would be orphaned)", res.Sessions[0].ID, res.Claims[0].SessionID)
	}
}

func FuzzIngest(f *testing.F) {
	f.Add(conversePair)
	f.Add(`{"output":{"outputBodyJson":{"content":[{"type":"tool_use"}]}}}`)
	f.Add(`[{"input":{"inputBodyJson":"oops"}}]`)
	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic on arbitrary input, only ever skip bad entries.
		_, _ = New(nil, Options{SessionKey: "session"}).Ingest(strings.NewReader(s), "fuzz")
	})
}
