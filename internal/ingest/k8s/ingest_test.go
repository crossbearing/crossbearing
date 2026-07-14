package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// eksSSOUser is how EKS spells an IAM-authenticated principal: the STS
// ARN, with the SSO login name sitting in the role-session slot. It reads
// like a person and is not one — every admin who assumes the role produces
// this same byte-identical username.
const eksSSOUser = "arn:aws:sts::351619759866:assumed-role/AWSReservedSSO_AdministratorAccess_1bd3786dce786114/sysadmin"

// eksEvent fabricates an EKS audit Event, including the user.extra map
// aws-iam-authenticator attaches. Shape taken verbatim from a live
// dev-eks audit log.
func eksEvent(id, verb, user, accessKey string, at time.Time) string {
	extra := ""
	if accessKey != "" {
		extra = fmt.Sprintf(`,"extra":{"accessKeyId":[%q],"arn":[%q],"canonicalArn":["arn:aws:iam::351619759866:role/AWSReservedSSO_AdministratorAccess_1bd3786dce786114"],"principalId":["AROAVDXRLX35N4FPX6ZV5"],"sessionName":["sysadmin"]}`, accessKey, user)
	}
	return fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":%q,"stage":"ResponseComplete","verb":%q,"requestURI":"/apis/apps/v1/namespaces/monitoring/daemonsets/alloy?fieldManager=kubectl-rollout","user":{"username":%q,"uid":"aws-iam-authenticator:351619759866:AROAVDXRLX35N4FPX6ZV5","groups":["system:authenticated"]%s},"sourceIPs":["162.197.3.60"],"userAgent":"kubectl/v1.32.2 (darwin/arm64)","objectRef":{"resource":"daemonsets","namespace":"monitoring","name":"alloy","apiGroup":"apps"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q,"stageTimestamp":%q}`,
		id, verb, user, extra, at.Format(time.RFC3339Nano), at.Add(50*time.Millisecond).Format(time.RFC3339Nano))
}

// The bug this pins: an EKS IAM principal is a shared credential, not a
// person. Binding it as the human would name an innocent role-session as
// the actor of an agent's production change — a fabricated attribution,
// which is worse than reporting none.
func TestIngest_EKSIAMPrincipalIsNeverAHuman(t *testing.T) {
	t.Parallel()
	res := ingest(t, Options{}, eksEvent("audit-1", "patch", eksSSOUser, "ASIAVDXRLX35EVQSBZ5N", t0)+"\n")

	s := res.Sessions[0]
	if s.Human != "" {
		t.Errorf("IAM role ARN bound as a human: %q — a shared SSO role is a credential, not a person", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrNone)
	}
}

// The access key is the only thing separating the agent's kubectl from
// Terraform (or a second engineer) when all three wear the same SSO role.
// It is also exactly what CloudTrail records, so it is the join between
// the two planes.
func TestIngest_AccessKeySeparatesASharedPrincipal(t *testing.T) {
	t.Parallel()
	const agentKey, terraformKey = "ASIAVDXRLX35EVQSBZ5N", "ASIAVDXRLX35HYL2W4X3"
	res := ingest(t, Options{}, strings.Join([]string{
		eksEvent("audit-1", "patch", eksSSOUser, agentKey, t0),
		eksEvent("audit-2", "get", eksSSOUser, terraformKey, t0.Add(time.Minute)),
		eksEvent("audit-3", "delete", eksSSOUser, agentKey, t0.Add(2*time.Minute)),
	}, "\n")+"\n")

	if len(res.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(res.Records))
	}
	if got := res.Records[0].AccessKeyID; got != agentKey {
		t.Errorf("Record.AccessKeyID = %q, want %q — the CloudTrail join key", got, agentKey)
	}
	// One username, one time window, two credential sessions.
	if len(res.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 (one per access key); a shared principal must not merge into one session", len(res.Sessions))
	}
	for _, s := range res.Sessions {
		if !strings.Contains(s.ID, agentKey) && !strings.Contains(s.ID, terraformKey) {
			t.Errorf("session ID %q names no access key; concurrent sessions would collide", s.ID)
		}
	}
}

// EKS delivers audit logs through CloudWatch, so the envelope — not bare
// audit JSONL — is the shape most real input arrives in. The Event rides
// inside as an escaped JSON string; without unwrapping, a 90 MB log
// ingests to exactly zero records and reports a clean cluster.
func TestIngest_CloudWatchEnvelope(t *testing.T) {
	t.Parallel()
	ev := eksEvent("audit-1", "patch", eksSSOUser, "ASIAVDXRLX35EVQSBZ5N", t0)
	msg, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, input string }{
		{"filter-log-events batch", fmt.Sprintf(`{"events":[{"logStreamName":"kube-apiserver-audit-fed9","timestamp":1783916490602,"message":%s}],"searchedLogStreams":[]}`, msg)},
		{"one envelope per line", fmt.Sprintf(`{"timestamp":1783916490602,"message":%s}`, msg)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := ingest(t, Options{}, tc.input)
			if len(res.Records) != 1 {
				t.Fatalf("records = %d, want 1 — the audit Event inside the CloudWatch envelope was not unwrapped", len(res.Records))
			}
			if res.Records[0].ID != "audit-1" {
				t.Errorf("ID = %q, want audit-1", res.Records[0].ID)
			}
			// Provenance must digest the Event, not the envelope: the
			// auditID identifies the Event, and that is what a re-fetch
			// returns.
			sum := sha256.Sum256([]byte(ev))
			if got, want := res.Records[0].Raw.Digest, hex.EncodeToString(sum[:]); got != want {
				t.Errorf("digest = %q, want the embedded Event's digest %q", got, want)
			}
		})
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

// Every kubectl invocation fires GET /api and GET /apis to discover the
// server's types before it does anything. They act on no resource, no agent
// claims them, and nothing can ever corroborate them — so recording them
// leaves a standing pile of unclaimed-record findings that can never be
// resolved and that bury the real ones. On the dev-eks corpus they were 822
// of 1,405 events.
func TestIngest_NonResourceRequestsAreNotActions(t *testing.T) {
	t.Parallel()
	nonResource := func(id, uri string) string {
		return fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":%q,"stage":"ResponseComplete","verb":"get","requestURI":%q,"user":{"username":%q},"responseStatus":{"code":200},"stageTimestamp":%q}`,
			id, uri, eksSSOUser, t0.Format(time.RFC3339Nano))
	}
	res := ingest(t, Options{}, strings.Join([]string{
		nonResource("disc-1", "/api"),
		nonResource("disc-2", "/apis"),
		nonResource("disc-3", "/version"),
		eksEvent("real-1", "patch", eksSSOUser, "ASIAVDXRLX35EVQSBZ5N", t0.Add(time.Second)),
	}, "\n")+"\n")

	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 — discovery calls are the client's machinery, not the agent's actions", len(res.Records))
	}
	if res.Records[0].ID != "real-1" {
		t.Errorf("ID = %q, want the one request that touched a resource", res.Records[0].ID)
	}
}

// One corrupt line used to abandon the rest of the stream, counted as a single
// bad doc — so a truncated line in a 100,000-line EKS export produced a
// confident report over the records before it and a warning that said "1". The
// report did not merely miss a divergence, it affirmatively denied one over
// input it never read. JSONL resyncs at the newline; the repo's own jsonl.go
// already does this for github/gcp/azure.
func TestIngest_CorruptLineDoesNotAbandonTheStream(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		eksEvent("audit-1", "patch", eksSSOUser, "ASIAKEY", t0),
		`{"kind":"Event","auditID":"audit-BROKEN","stage":"Respo`, // truncated mid-write
		eksEvent("audit-2", "delete", eksSSOUser, "ASIAKEY", t0.Add(time.Minute)),
		eksEvent("audit-3", "create", eksSSOUser, "ASIAKEY", t0.Add(2*time.Minute)),
	}, "\n") + "\n"

	res := ingest(t, Options{}, input)

	if len(res.Records) != 3 {
		t.Fatalf("records = %d, want 3 — the corrupt line must cost one line, not the rest of the log", len(res.Records))
	}
	for i, want := range []string{"audit-1", "audit-2", "audit-3"} {
		if res.Records[i].ID != want {
			t.Errorf("record[%d].ID = %q, want %q", i, res.Records[i].ID, want)
		}
	}
}
