package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

var t0 = time.Date(2026, 6, 10, 17, 0, 0, 0, time.UTC)

const (
	agentSP  = "11111111-2222-3333-4444-555555555555" // a service principal / managed identity caller (GUID)
	vmResID  = "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/api"
	writeVM  = "Microsoft.Compute/virtualMachines/write"
	deleteVM = "Microsoft.Compute/virtualMachines/delete"
)

// event fabricates an EventData object in the `az monitor activity-log
// list -o json` shape. A non-empty human seeds the upn claim.
func event(id, op, caller, human, resID, status string, at time.Time) string {
	claims := ""
	if human != "" {
		claims = fmt.Sprintf(`,"claims":{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn":%q,"appid":%q}`, human, agentSP)
	}
	st := ""
	if status != "" {
		st = fmt.Sprintf(`,"status":{"value":%q}`, status)
	}
	return fmt.Sprintf(`{"eventDataId":%q,"eventTimestamp":%q,"operationName":{"value":%q},"resourceId":%q,"resourceGroupName":"prod-rg","caller":%q,"level":"Informational"%s%s}`,
		id, at.Format(time.RFC3339Nano), op, resID, caller, st, claims)
}

func runIngest(t *testing.T, opts Options, input string) Result {
	t.Helper()
	if opts.Subscription == "" {
		opts.Subscription = "sub-1"
	}
	res, err := New(nil, opts).Ingest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	return res
}

func TestIngest_RecordShape(t *testing.T) {
	t.Parallel()
	line := event("evt-1", writeVM, agentSP, "bs@example.com", vmResID, "Succeeded", t0)
	res := runIngest(t, Options{}, line+"\n")

	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	r := res.Records[0]
	if r.ID != "evt-1" {
		t.Errorf("ID = %q, want evt-1", r.ID)
	}
	if r.Source != corroborate.SourceAzureActivity {
		t.Errorf("Source = %q, want %q", r.Source, corroborate.SourceAzureActivity)
	}
	if want := "azure-activity:" + writeVM; r.Operation != want {
		t.Errorf("Operation = %q, want %q", r.Operation, want)
	}
	if r.Principal != agentSP {
		t.Errorf("Principal = %q, want the workload caller", r.Principal)
	}
	if r.SourceIdentity != "bs@example.com" {
		t.Errorf("SourceIdentity = %q, want the delegated human from claims", r.SourceIdentity)
	}
	if len(r.Targets) != 1 || r.Targets[0] != vmResID {
		t.Errorf("Targets = %v", r.Targets)
	}
	if want := "azure-activity:sub-1#evt-1"; r.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", r.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(line))
	if r.Raw.Digest != hex.EncodeToString(sum[:]) {
		t.Error("Digest is not the sha256 of the raw entry bytes")
	}
}

func TestIngest_JSONArrayShape(t *testing.T) {
	t.Parallel()
	input := "[\n" + event("evt-1", writeVM, agentSP, "", vmResID, "Succeeded", t0) + ",\n" +
		event("evt-2", deleteVM, agentSP, "", vmResID, "Succeeded", t0.Add(time.Minute)) + "\n]"
	res := runIngest(t, Options{}, input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2 from the az-cli array shape", len(res.Records))
	}
}

func TestIngest_OnlyEffectiveRecords(t *testing.T) {
	t.Parallel()
	// A real Azure resource op logs Started → Accepted → Succeeded for one
	// action; only the terminal Succeeded may record, or it double-counts.
	// Failed (denial) and the ServiceHealth platform statuses drop too.
	res := runIngest(t, Options{},
		event("evt-start", deleteVM, agentSP, "", vmResID, "Started", t0)+"\n"+
			event("evt-accepted", deleteVM, agentSP, "", vmResID, "Accepted", t0)+"\n"+
			event("evt-fail", deleteVM, agentSP, "", vmResID, "Failed", t0)+"\n"+
			event("evt-active", "Microsoft.ServiceHealth/incident/action", agentSP, "", vmResID, "Active", t0)+"\n"+
			event("evt-resolved", "Microsoft.ServiceHealth/incident/action", agentSP, "", vmResID, "Resolved", t0)+"\n"+
			event("evt-ok", deleteVM, agentSP, "", vmResID, "Succeeded", t0)+"\n")
	if len(res.Records) != 1 || res.Records[0].ID != "evt-ok" {
		t.Fatalf("records = %+v, want only the terminal Succeeded operation", res.Records)
	}
}

func TestIngest_MicrosoftPlatformCallerNotHuman(t *testing.T) {
	t.Parallel()
	// A Microsoft first-party caller (AcmClient@microsoft.com) has a UPN
	// shape but is not the customer's operator — must not bind as a human.
	res := runIngest(t, Options{},
		event("evt-1", writeVM, "AcmClient@microsoft.com", "", vmResID, "Succeeded", t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("Microsoft platform caller bound as human=%q via %q", s.Human, s.Attribution.Method)
	}
}

func TestIngest_DelegationBinding(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		event("evt-1", writeVM, agentSP, "bs@example.com", vmResID, "Succeeded", t0)+"\n"+
			event("evt-2", deleteVM, agentSP, "bs@example.com", vmResID, "Succeeded", t0.Add(time.Minute))+"\n")

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.Human != "bs@example.com" {
		t.Errorf("Human = %q, want the delegated identity from claims", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrAzureDelegation {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrAzureDelegation)
	}
	if len(s.Attribution.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both event IDs", s.Attribution.Evidence)
	}
	if s.Agent != agentSP {
		t.Errorf("Agent = %q, want the workload caller", s.Agent)
	}
}

func TestIngest_BareWorkloadUnattributed(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		event("evt-1", writeVM, agentSP, "", vmResID, "Succeeded", t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("bare workload bound: Human=%q Method=%q, want unattributed (the gap)", s.Human, s.Attribution.Method)
	}
}

func TestIngest_HumanCallerBindsToItself(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		event("evt-1", "Microsoft.Resources/subscriptions/resourceGroups/read", "carol@example.com", "", vmResID, "Succeeded", t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "carol@example.com" {
		t.Errorf("Human = %q, want the authenticated UPN caller", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrActorIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrActorIdentity)
	}
	// The caller is itself the human; the SourceIdentity slot stays empty.
	if res.Records[0].SourceIdentity != "" {
		t.Errorf("SourceIdentity = %q, want empty for a direct human caller", res.Records[0].SourceIdentity)
	}
}

func TestIngest_NameClaimFallback(t *testing.T) {
	t.Parallel()
	// No upn claim, but the name claim carries a UPN-shaped value.
	line := fmt.Sprintf(`{"eventDataId":"evt-1","eventTimestamp":%q,"operationName":{"value":%q},"resourceId":%q,"caller":%q,"status":{"value":"Succeeded"},"claims":{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":"dora@example.com"}}`,
		t0.Format(time.RFC3339), writeVM, vmResID, agentSP)
	res := runIngest(t, Options{}, line+"\n")
	if s := res.Sessions[0]; s.Human != "dora@example.com" || s.Attribution.Method != corroborate.AttrAzureDelegation {
		t.Errorf("name-claim fallback: Human=%q Method=%q", s.Human, s.Attribution.Method)
	}
}

func TestIngest_ProductionScope(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{IsProduction: func(s string) bool { return strings.Contains(s, "/prod-rg/") }},
		event("evt-1", writeVM, agentSP, "", vmResID, "Succeeded", t0)+"\n")
	if !res.Records[0].ProductionTouching {
		t.Error("ProductionTouching = false for a prod-rg resource")
	}
}

func TestIngest_GapSplitsSessions(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{SessionGap: 30 * time.Minute},
		event("evt-1", writeVM, agentSP, "", vmResID, "Succeeded", t0)+"\n"+
			event("evt-2", writeVM, agentSP, "", vmResID, "Succeeded", t0.Add(2*time.Hour))+"\n")
	if len(res.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 across a 2h gap", len(res.Sessions))
	}
}

func TestIngest_MalformedAndIncompleteEntries(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		"{not json\n"+
			`{"eventDataId":"evt-x","operationName":{"value":"Microsoft.Compute/virtualMachines/read"}}`+"\n"+ // no caller
			event("evt-1", writeVM, agentSP, "", vmResID, "Succeeded", t0)+"\n")
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
