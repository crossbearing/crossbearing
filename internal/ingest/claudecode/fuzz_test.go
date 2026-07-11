package claudecode

import (
	"strings"
	"testing"
)

func FuzzIngest(f *testing.F) {
	f.Add(`{"type":"assistant","sessionId":"s","uuid":"u1","timestamp":"2026-06-10T03:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"aws sts get-caller-identity"}}]}}`)
	f.Add(`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1"}]}}`)
	f.Add("not json\n{bad")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, data string) {
		res, err := New(nil, Options{DeclaredOperator: "op@x"}).Ingest(strings.NewReader(data), "fuzz")
		if err != nil {
			return
		}
		for _, c := range res.Claims {
			if c.ID == "" || c.Operation == "" {
				t.Fatalf("emitted a claim with empty identity: %+v", c)
			}
		}
	})
}
