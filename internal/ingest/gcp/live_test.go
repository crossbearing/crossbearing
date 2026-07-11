package gcp

import (
	"os"
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// TestLive_IngestAuditLog validates the ingester against a real project's
// Cloud Audit Logs — the schema and the shapes fixtures can't anticipate:
// the real LogEntry/AuditLog nesting, gRPC status codes (NOT HTTP — a
// failed op carries a non-zero google.rpc code), and real principal and
// methodName variety.
//
// Skipped unless CROSSBEARING_GCP_AUDIT points at the JSON `gcloud
// logging read` emits:
//
//	gcloud logging read 'logName=~"cloudaudit.googleapis.com"' \
//	  --project <id> --format=json --limit 200 --freshness=90d > g.json
//	CROSSBEARING_GCP_AUDIT=g.json go test ./internal/ingest/gcp -run TestLive -v
func TestLive_IngestAuditLog(t *testing.T) {
	path := os.Getenv("CROSSBEARING_GCP_AUDIT")
	if path == "" {
		t.Skip("set CROSSBEARING_GCP_AUDIT to a real audit-log file to run")
	}

	res, err := New(nil, Options{Project: "live"}).IngestFile(path)
	if err != nil {
		t.Fatalf("IngestFile: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("no records from a real audit log")
	}

	seen := map[string]bool{}
	for _, r := range res.Records {
		if r.ID == "" || r.Operation == "" || r.Principal == "" || r.Raw.Digest == "" || r.RecordedAt.IsZero() {
			t.Fatalf("record missing identity/provenance: %+v", r)
		}
		if !strings.HasPrefix(r.Operation, "gcp-audit:") {
			t.Fatalf("operation %q not in record vocabulary", r.Operation)
		}
		if seen[r.ID] {
			t.Errorf("duplicate record ID %s", r.ID)
		}
		seen[r.ID] = true
	}

	var actor, delegated, unattributed int
	for _, s := range res.Sessions {
		switch s.Attribution.Method {
		case corroborate.AttrActorIdentity:
			actor++
		case corroborate.AttrGCPDelegation:
			delegated++
		case corroborate.AttrNone:
			unattributed++
		}
	}
	t.Logf("records: %d · sessions: %d (actor %d, delegation %d, unattributed %d)",
		len(res.Records), len(res.Sessions), actor, delegated, unattributed)
}
