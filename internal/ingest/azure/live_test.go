package azure

import (
	"os"
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// TestLive_IngestActivityLog validates the ingester against a real Azure
// Activity Log — the shapes fixtures can't anticipate: the real EventData
// schema, the Started→Accepted→Succeeded status triple that must dedup to
// one record, Microsoft first-party callers, and bare workload identities.
//
// Skipped unless CROSSBEARING_AZURE_AUDIT points at the JSON `az monitor
// activity-log list -o json` emits:
//
//	az monitor activity-log list --offset 30d --max-events 200 -o json > a.json
//	CROSSBEARING_AZURE_AUDIT=a.json go test ./internal/ingest/azure -run TestLive -v
func TestLive_IngestActivityLog(t *testing.T) {
	path := os.Getenv("CROSSBEARING_AZURE_AUDIT")
	if path == "" {
		t.Skip("set CROSSBEARING_AZURE_AUDIT to a real activity-log file to run")
	}

	res, err := New(nil, Options{Subscription: "live"}).IngestFile(path)
	if err != nil {
		t.Fatalf("IngestFile: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("no records from a real activity log")
	}

	seen := map[string]bool{}
	for _, r := range res.Records {
		if r.ID == "" || r.Operation == "" || r.Principal == "" || r.Raw.Digest == "" || r.RecordedAt.IsZero() {
			t.Fatalf("record missing identity/provenance: %+v", r)
		}
		if !strings.HasPrefix(r.Operation, "azure-activity:") {
			t.Fatalf("operation %q not in record vocabulary", r.Operation)
		}
		if seen[r.ID] {
			t.Errorf("duplicate record ID %s (status dedup failed)", r.ID)
		}
		seen[r.ID] = true
	}

	var actor, delegated, unattributed int
	for _, s := range res.Sessions {
		if strings.HasSuffix(s.Human, "@microsoft.com") {
			t.Errorf("session bound to a Microsoft platform caller: %s", s.Human)
		}
		switch s.Attribution.Method {
		case corroborate.AttrActorIdentity:
			actor++
		case corroborate.AttrAzureDelegation:
			delegated++
		case corroborate.AttrNone:
			unattributed++
		}
	}
	t.Logf("records: %d · sessions: %d (actor %d, delegation %d, unattributed %d)",
		len(res.Records), len(res.Sessions), actor, delegated, unattributed)
}
