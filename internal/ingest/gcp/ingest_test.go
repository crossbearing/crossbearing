package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

var t0 = time.Date(2026, 6, 10, 16, 0, 0, 0, time.UTC)

const agentSA = "agent-deployer@my-project.iam.gserviceaccount.com"

// auditEntry fabricates a Cloud Logging LogEntry wrapping an AuditLog,
// in the shape `gcloud logging read --format=json` emits.
func auditEntry(id, method, principal, delegatedHuman, resource string, code int, at time.Time) string {
	delegation := ""
	if delegatedHuman != "" {
		delegation = fmt.Sprintf(`,"serviceAccountDelegationInfo":[{"firstPartyPrincipal":{"principalEmail":%q}}]`, delegatedHuman)
	}
	status := ""
	if code != 0 {
		status = fmt.Sprintf(`,"status":{"code":%d,"message":"denied"}`, code)
	}
	return fmt.Sprintf(`{"insertId":%q,"timestamp":%q,"logName":"projects/my-project/logs/cloudaudit.googleapis.com%%2Factivity","resource":{"type":"gcs_bucket","labels":{"project_id":"my-project"}},"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","serviceName":"storage.googleapis.com","methodName":%q,"resourceName":%q,"authenticationInfo":{"principalEmail":%q%s}%s}}`,
		id, at.Format(time.RFC3339Nano), method, resource, principal, delegation, status)
}

func runIngest(t *testing.T, opts Options, input string) Result {
	t.Helper()
	if opts.Project == "" {
		opts.Project = "my-project"
	}
	res, err := New(nil, opts).Ingest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	return res
}

func TestIngest_RecordShape(t *testing.T) {
	t.Parallel()
	line := auditEntry("ins-1", "storage.objects.create", agentSA, "bs@example.com",
		"projects/_/buckets/prod-artifacts/objects/release.tar.gz", 0, t0)
	res := runIngest(t, Options{}, line+"\n")

	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	r := res.Records[0]
	if r.ID != "ins-1" {
		t.Errorf("ID = %q, want ins-1", r.ID)
	}
	if r.Source != corroborate.SourceGCPAudit {
		t.Errorf("Source = %q, want %q", r.Source, corroborate.SourceGCPAudit)
	}
	if want := "gcp-audit:storage.objects.create"; r.Operation != want {
		t.Errorf("Operation = %q, want %q", r.Operation, want)
	}
	if r.Principal != agentSA {
		t.Errorf("Principal = %q, want the acting SA", r.Principal)
	}
	if r.SourceIdentity != "bs@example.com" {
		t.Errorf("SourceIdentity = %q, want the delegated human", r.SourceIdentity)
	}
	if len(r.Targets) != 1 || !strings.Contains(r.Targets[0], "release.tar.gz") {
		t.Errorf("Targets = %v", r.Targets)
	}
	if want := "gcp-audit:my-project#ins-1"; r.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", r.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(line))
	if r.Raw.Digest != hex.EncodeToString(sum[:]) {
		t.Error("Digest is not the sha256 of the raw entry bytes")
	}
}

func TestIngest_JSONArrayShape(t *testing.T) {
	t.Parallel()
	input := "[\n" + auditEntry("ins-1", "storage.objects.create", agentSA, "bs@example.com", "r1", 0, t0) + ",\n" +
		auditEntry("ins-2", "storage.objects.delete", agentSA, "bs@example.com", "r1", 0, t0.Add(time.Minute)) + "\n]"
	res := runIngest(t, Options{}, input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2 from the gcloud array shape", len(res.Records))
	}
}

func TestIngest_OnlySuccessfulRecords(t *testing.T) {
	t.Parallel()
	denied := auditEntry("ins-denied", "storage.objects.delete", agentSA, "", "r1", 7, t0) // PERMISSION_DENIED
	ok := auditEntry("ins-ok", "storage.objects.create", agentSA, "", "r1", 0, t0)
	res := runIngest(t, Options{}, denied+"\n"+ok+"\n")
	if len(res.Records) != 1 || res.Records[0].ID != "ins-ok" {
		t.Fatalf("records = %+v, want only the successful call", res.Records)
	}
}

func TestIngest_LongRunningOperationRecordsOnceAtCompletion(t *testing.T) {
	t.Parallel()
	// An async op: a "first" slice and a "last" slice share an operation id.
	mk := func(id string, first, last bool, at time.Time) string {
		op := fmt.Sprintf(`,"operation":{"id":"op-42","first":%v,"last":%v}`, first, last)
		base := auditEntry(id, "compute.instances.insert", agentSA, "", "instances/vm-1", 0, at)
		return base[:len(base)-1] + op + "}"
	}
	res := runIngest(t, Options{},
		mk("ins-first", true, false, t0)+"\n"+
			mk("ins-last", false, true, t0.Add(2*time.Minute))+"\n")
	if len(res.Records) != 1 || res.Records[0].ID != "ins-last" {
		t.Fatalf("records = %+v, want only the completion slice", res.Records)
	}
}

func TestIngest_DelegationBinding(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		auditEntry("ins-1", "storage.objects.create", agentSA, "bs@example.com", "r1", 0, t0)+"\n"+
			auditEntry("ins-2", "storage.objects.delete", agentSA, "bs@example.com", "r1", 0, t0.Add(time.Minute))+"\n")

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.Human != "bs@example.com" {
		t.Errorf("Human = %q, want the delegated identity", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrGCPDelegation {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrGCPDelegation)
	}
	if len(s.Attribution.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both insert IDs", s.Attribution.Evidence)
	}
	if s.Agent != agentSA {
		t.Errorf("Agent = %q, want the acting SA", s.Agent)
	}
}

func TestIngest_BareServiceAccountUnattributed(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		auditEntry("ins-1", "storage.objects.create", agentSA, "", "r1", 0, t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("bare SA bound: Human=%q Method=%q, want unattributed (the gap)", s.Human, s.Attribution.Method)
	}
}

func TestIngest_HumanPrincipalBindsToItself(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		auditEntry("ins-1", "storage.buckets.get", "carol@example.com", "", "r1", 0, t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "carol@example.com" {
		t.Errorf("Human = %q, want the authenticated user", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrActorIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrActorIdentity)
	}
}

func TestIngest_GoogleManagedPrincipalsNotHuman(t *testing.T) {
	t.Parallel()
	for _, p := range []string{
		"service-123456@gcp-sa-cloudbuild.iam.gserviceaccount.com",
		"system:serviceaccount",
		"123-compute@developer.gserviceaccount.com",
	} {
		res := runIngest(t, Options{}, auditEntry("ins-1", "storage.objects.create", p, "", "r1", 0, t0)+"\n")
		if s := res.Sessions[0]; s.Human != "" {
			t.Errorf("principal %q bound to itself as %q", p, s.Human)
		}
	}
}

func TestIngest_ProjectFallsBackToResourceLabel(t *testing.T) {
	t.Parallel()
	// No Project option: the locator must use the entry's own project_id.
	res, err := New(nil, Options{}).Ingest(strings.NewReader(
		auditEntry("ins-1", "storage.objects.create", agentSA, "", "r1", 0, t0) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "gcp-audit:my-project#ins-1"; res.Records[0].Raw.Locator != want {
		t.Errorf("Locator = %q, want %q (from resource.labels)", res.Records[0].Raw.Locator, want)
	}
}

func TestIngest_ProductionScope(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{IsProduction: func(t string) bool { return strings.Contains(t, "prod-") }},
		auditEntry("ins-1", "storage.objects.create", agentSA, "", "projects/_/buckets/prod-data/objects/x", 0, t0)+"\n")
	if !res.Records[0].ProductionTouching {
		t.Error("ProductionTouching = false for a prod- bucket target")
	}
}

func TestIngest_GapSplitsSessions(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{SessionGap: 30 * time.Minute},
		auditEntry("ins-1", "storage.objects.create", agentSA, "", "r1", 0, t0)+"\n"+
			auditEntry("ins-2", "storage.objects.create", agentSA, "", "r1", 0, t0.Add(2*time.Hour))+"\n")
	if len(res.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 across a 2h gap", len(res.Sessions))
	}
}

func TestIngest_MalformedAndIncompleteEntries(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		"{not json\n"+
			`{"insertId":"ins-x","protoPayload":{"methodName":"storage.objects.get"}}`+"\n"+ // no principal
			auditEntry("ins-1", "storage.objects.create", agentSA, "", "r1", 0, t0)+"\n")
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 (malformed and incomplete skipped)", len(res.Records))
	}
}

func TestIngest_EmptyInput(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{}, "")
	if len(res.Records) != 0 || len(res.Sessions) != 0 {
		t.Fatalf("empty input produced %d records, %d sessions", len(res.Records), len(res.Sessions))
	}
}
