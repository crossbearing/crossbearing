package k8s

import (
	"os"
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// TestLive_IngestAuditLog validates the ingester against a real
// kube-apiserver audit log — the shapes fixtures can drift from: the
// control plane's own event firehose, real RBAC annotations, real
// impersonation events from an agent ServiceAccount wearing
// Impersonate-User headers.
//
// Skipped unless CROSSBEARING_K8S_AUDIT points at an audit log (the kind
// recipe that produces one lives in the commit message introducing this
// test). Optional knobs pin the convention assertions to the fixture
// cluster's identities:
//
//	CROSSBEARING_K8S_AUDIT=/tmp/cb-audit/audit.log \
//	CROSSBEARING_K8S_AGENT_SA=system:serviceaccount:agents:claude-code \
//	CROSSBEARING_K8S_HUMAN=bs@example.com \
//	  go test ./internal/ingest/k8s -run TestLive -v
func TestLive_IngestAuditLog(t *testing.T) {
	path := os.Getenv("CROSSBEARING_K8S_AUDIT")
	if path == "" {
		t.Skip("set CROSSBEARING_K8S_AUDIT to a kube-apiserver audit log to run")
	}

	g := New(nil, Options{Cluster: "live"})
	res, err := g.IngestFile(path)
	if err != nil {
		t.Fatalf("IngestFile: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("no records from a live audit log")
	}

	// Every record must satisfy the provenance hard rule, and only
	// effective requests may exist.
	for _, r := range res.Records {
		if r.ID == "" || r.Raw.Digest == "" || r.Raw.Locator == "" || r.RecordedAt.IsZero() {
			t.Fatalf("record missing identity/provenance: %+v", r)
		}
		if !strings.HasPrefix(r.Operation, "k8s-audit:") {
			t.Fatalf("operation %q not in record vocabulary", r.Operation)
		}
	}

	var (
		agentSA = os.Getenv("CROSSBEARING_K8S_AGENT_SA")
		human   = os.Getenv("CROSSBEARING_K8S_HUMAN")

		impersonated, actorIdentity, unattributed int
		agentSessionOK                            bool
	)
	for _, s := range res.Sessions {
		switch s.Attribution.Method {
		case corroborate.AttrK8sImpersonation:
			impersonated++
			if agentSA != "" && s.Agent == agentSA {
				if human != "" && s.Human != human {
					t.Errorf("agent session bound to %q, want %q", s.Human, human)
				}
				if len(s.Attribution.Evidence) == 0 {
					t.Error("impersonation binding carries no evidence")
				}
				agentSessionOK = true
			}
		case corroborate.AttrActorIdentity:
			actorIdentity++
			if strings.HasPrefix(s.Agent, "system:") {
				t.Errorf("system identity %q bound to itself", s.Agent)
			}
		case corroborate.AttrNone:
			unattributed++
		}
	}
	t.Logf("records: %d · sessions: %d (impersonation %d, actor-identity %d, unattributed %d)",
		len(res.Records), len(res.Sessions), impersonated, actorIdentity, unattributed)

	if agentSA != "" && !agentSessionOK {
		t.Errorf("no impersonation-bound session for agent %q", agentSA)
	}
	if impersonated == 0 && agentSA != "" {
		t.Error("live log produced no k8s-impersonation bindings")
	}
}
