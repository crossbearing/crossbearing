package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

var t0 = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)

const agentSA = "system:serviceaccount:agents:claude-code"

// auditEvent fabricates one audit.k8s.io/v1 Event in the log-backend shape.
func auditEvent(id, verb, user, impersonated string, code int, at time.Time) string {
	imp := ""
	if impersonated != "" {
		imp = fmt.Sprintf(`"impersonatedUser":{"username":%q,"groups":["system:authenticated"]},`, impersonated)
	}
	return fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":%q,"stage":"ResponseComplete","verb":%q,"requestURI":"/apis/apps/v1/namespaces/prod/deployments/api","user":{"username":%q},%s"objectRef":{"resource":"deployments","namespace":"prod","name":"api","apiGroup":"apps"},"responseStatus":{"code":%d},"requestReceivedTimestamp":%q,"stageTimestamp":%q}`,
		id, verb, user, imp, code, at.Format(time.RFC3339Nano), at.Add(50*time.Millisecond).Format(time.RFC3339Nano))
}

func ingest(t *testing.T, opts Options, input string) Result {
	t.Helper()
	if opts.Cluster == "" {
		opts.Cluster = "prod-east"
	}
	res, err := New(nil, opts).Ingest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	return res
}

func TestIngest_RecordShape(t *testing.T) {
	t.Parallel()
	line := auditEvent("audit-1", "create", agentSA, "bs@example.com", 201, t0)
	res := ingest(t, Options{}, line+"\n")

	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	r := res.Records[0]
	if r.ID != "audit-1" {
		t.Errorf("ID = %q, want audit-1", r.ID)
	}
	if r.Source != corroborate.SourceK8sAudit {
		t.Errorf("Source = %q, want %q", r.Source, corroborate.SourceK8sAudit)
	}
	if want := "k8s-audit:create:deployments"; r.Operation != want {
		t.Errorf("Operation = %q, want %q", r.Operation, want)
	}
	if r.Principal != agentSA {
		t.Errorf("Principal = %q, want the authenticating SA", r.Principal)
	}
	if r.SourceIdentity != "bs@example.com" {
		t.Errorf("SourceIdentity = %q, want the impersonated human", r.SourceIdentity)
	}
	if len(r.Targets) != 1 || r.Targets[0] != "prod/deployments/api" {
		t.Errorf("Targets = %v, want [prod/deployments/api]", r.Targets)
	}
	if want := "k8s-audit:prod-east#audit-1"; r.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", r.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(line))
	if r.Raw.Digest != hex.EncodeToString(sum[:]) {
		t.Error("Digest is not the sha256 of the raw event bytes")
	}
}

func TestIngest_OnlyEffectiveRequestsRecord(t *testing.T) {
	t.Parallel()
	denied := auditEvent("audit-denied", "delete", agentSA, "", 403, t0)
	received := strings.Replace(
		auditEvent("audit-rr", "create", agentSA, "", 0, t0), `"stage":"ResponseComplete"`, `"stage":"RequestReceived"`, 1)
	ok := auditEvent("audit-ok", "create", agentSA, "", 201, t0)

	res := ingest(t, Options{}, denied+"\n"+received+"\n"+ok+"\n")
	if len(res.Records) != 1 || res.Records[0].ID != "audit-ok" {
		t.Fatalf("records = %+v, want only the completed successful request", res.Records)
	}
}

func TestIngest_NoPrincipalDropped(t *testing.T) {
	t.Parallel()
	// An event with no user.username (anonymous / stripped) must not
	// become a Record with an empty Principal — found by FuzzIngest.
	line := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a1","stage":"ResponseComplete","verb":"get","objectRef":{"resource":"pods"},"responseStatus":{"code":200},"stageTimestamp":"2026-06-10T15:00:00Z"}`
	res := ingest(t, Options{}, line+"\n")
	if len(res.Records) != 0 {
		t.Fatalf("records = %d, want 0 for a principal-less event", len(res.Records))
	}
}

func TestIngest_ImpersonationBinding(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		auditEvent("audit-1", "create", agentSA, "bs@example.com", 201, t0)+"\n"+
			auditEvent("audit-2", "patch", agentSA, "bs@example.com", 200, t0.Add(time.Minute))+"\n")

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.Human != "bs@example.com" {
		t.Errorf("Human = %q, want the impersonated identity", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrK8sImpersonation {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrK8sImpersonation)
	}
	if len(s.Attribution.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both audit IDs", s.Attribution.Evidence)
	}
	if s.Agent != agentSA {
		t.Errorf("Agent = %q, want the SA credential", s.Agent)
	}
}

func TestIngest_BareSATokenIsUnattributed(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		auditEvent("audit-1", "create", agentSA, "", 201, t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("bare SA bound: Human=%q Method=%q, want unattributed (the convention gap)", s.Human, s.Attribution.Method)
	}
}

func TestIngest_OIDCUserBindsToItself(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		auditEvent("audit-1", "get", "carol@example.com", "", 200, t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "carol@example.com" {
		t.Errorf("Human = %q, want the authenticated OIDC user", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrActorIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrActorIdentity)
	}
}

func TestIngest_SystemUsersNeverBindToThemselves(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		auditEvent("audit-1", "update", "system:kube-controller-manager", "", 200, t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" {
		t.Errorf("system identity bound to itself: %q", s.Human)
	}
}

func TestIngest_EventListShape(t *testing.T) {
	t.Parallel()
	list := fmt.Sprintf(`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[%s,
	  %s]}`,
		auditEvent("audit-1", "create", agentSA, "", 201, t0),
		auditEvent("audit-2", "delete", agentSA, "", 200, t0.Add(time.Minute)))
	res := ingest(t, Options{}, list)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2 from a multi-line EventList", len(res.Records))
	}
}

func TestIngest_GapSplitsSessions(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{SessionGap: 30 * time.Minute},
		auditEvent("audit-1", "create", agentSA, "", 201, t0)+"\n"+
			auditEvent("audit-2", "create", agentSA, "", 201, t0.Add(3*time.Hour))+"\n")
	if len(res.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 across a 3h gap", len(res.Sessions))
	}
}

func TestIngest_ProductionScope(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{IsProduction: func(target string) bool { return strings.HasPrefix(target, "prod/") }},
		auditEvent("audit-1", "delete", agentSA, "", 200, t0)+"\n")
	if !res.Records[0].ProductionTouching {
		t.Error("ProductionTouching = false for a prod/ namespace target")
	}
}

func TestIngest_MalformedTailCounted(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{},
		auditEvent("audit-1", "create", agentSA, "", 201, t0)+"\n{not json")
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 before the malformed tail", len(res.Records))
	}
}

func TestIngest_EmptyInput(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{}, "")
	if len(res.Records) != 0 || len(res.Sessions) != 0 {
		t.Fatalf("empty input produced %d records, %d sessions", len(res.Records), len(res.Sessions))
	}
}
