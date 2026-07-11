package github

import (
	"os"
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// TestLive_IngestAuditLog validates the ingester against a real org audit
// log export (Settings → Audit log → Export → JSON, gunzipped to JSONL).
// Skipped unless CROSSBEARING_GITHUB_AUDIT is set.
//
//	CROSSBEARING_GITHUB_AUDIT=audit.jsonl CROSSBEARING_GITHUB_ORG=myorg \
//	  go test ./internal/ingest/github -run TestLive -v
func TestLive_IngestAuditLog(t *testing.T) {
	path := os.Getenv("CROSSBEARING_GITHUB_AUDIT")
	if path == "" {
		t.Skip("set CROSSBEARING_GITHUB_AUDIT to a real audit-log export to run")
	}
	org := os.Getenv("CROSSBEARING_GITHUB_ORG")

	res, err := New(nil, Options{Org: org}).IngestFile(path)
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
		if !strings.HasPrefix(r.Operation, "github-audit:") {
			t.Fatalf("operation %q not in record vocabulary", r.Operation)
		}
		if seen[r.ID] {
			t.Errorf("duplicate record ID %s", r.ID)
		}
		seen[r.ID] = true
	}

	var actor, mapped, unattributed int
	for _, s := range res.Sessions {
		if s.Human == "ghost" || (org != "" && s.Human == org) {
			t.Errorf("bound a non-human actor as human: %q", s.Human)
		}
		switch s.Attribution.Method {
		case corroborate.AttrActorIdentity:
			actor++
		case corroborate.AttrGitHubApp:
			mapped++
		case corroborate.AttrNone:
			unattributed++
		}
	}
	t.Logf("records: %d · sessions: %d (actor %d, app-mapped %d, unattributed %d)",
		len(res.Records), len(res.Sessions), actor, mapped, unattributed)
}
