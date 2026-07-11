package github

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

var t0 = time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)

// auditEntry fabricates one audit-log entry in the API/export shape.
func auditEntry(id, action, actor, repo string, at time.Time) string {
	return fmt.Sprintf(`{"@timestamp":%d,"_document_id":%q,"action":%q,"actor":%q,"org":"crossbearing","repo":%q,"operation_type":"create"}`,
		at.UnixMilli(), id, action, actor, repo)
}

func runIngest(t *testing.T, opts Options, input string) Result {
	t.Helper()
	if opts.Org == "" {
		opts.Org = "crossbearing"
	}
	res, err := New(nil, opts).Ingest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	return res
}

func TestIngest_JSONLRecord(t *testing.T) {
	t.Parallel()
	line := auditEntry("doc-1", "repo.create", "stxkxs", "crossbearing/engine", t0)
	res := runIngest(t, Options{}, line+"\n")

	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	r := res.Records[0]
	if r.ID != "doc-1" {
		t.Errorf("ID = %q, want doc-1", r.ID)
	}
	if r.Source != corroborate.SourceGitHubAudit {
		t.Errorf("Source = %q, want %q", r.Source, corroborate.SourceGitHubAudit)
	}
	if want := "github-audit:repo.create"; r.Operation != want {
		t.Errorf("Operation = %q, want %q", r.Operation, want)
	}
	if r.Principal != "stxkxs" {
		t.Errorf("Principal = %q, want stxkxs", r.Principal)
	}
	if len(r.Targets) != 2 || r.Targets[0] != "crossbearing/engine" {
		t.Errorf("Targets = %v, want repo then org", r.Targets)
	}
	if !r.RecordedAt.Equal(t0) {
		t.Errorf("RecordedAt = %v, want %v", r.RecordedAt, t0)
	}
	if want := "github-audit:crossbearing#doc-1"; r.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", r.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(line))
	if r.Raw.Digest != hex.EncodeToString(sum[:]) {
		t.Error("Digest is not the sha256 of the raw entry bytes")
	}
}

func TestIngest_JSONArrayShape(t *testing.T) {
	t.Parallel()
	input := "[\n" + auditEntry("doc-1", "repo.create", "stxkxs", "r1", t0) + ",\n" +
		auditEntry("doc-2", "git.push", "stxkxs", "r1", t0.Add(time.Minute)) + "\n]"
	res := runIngest(t, Options{}, input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2 from the API array shape", len(res.Records))
	}
}

func TestIngest_HumanActorBindsToItself(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		auditEntry("doc-1", "repo.create", "stxkxs", "r1", t0)+"\n"+
			auditEntry("doc-2", "git.push", "stxkxs", "r1", t0.Add(time.Minute))+"\n")

	if len(res.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(res.Sessions))
	}
	s := res.Sessions[0]
	if s.Human != "stxkxs" {
		t.Errorf("Human = %q, want the authenticated actor", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrActorIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrActorIdentity)
	}
	if len(s.Attribution.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both document IDs", s.Attribution.Evidence)
	}
	if s.Agent != "stxkxs" {
		t.Errorf("Agent = %q", s.Agent)
	}
}

func TestIngest_BotBindsOnlyViaMapping(t *testing.T) {
	t.Parallel()
	input := auditEntry("doc-1", "pull_request.merge", "deployer[bot]", "r1", t0) + "\n"

	unmapped := runIngest(t, Options{}, input)
	if s := unmapped.Sessions[0]; s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("unmapped bot bound: Human=%q Method=%q, want unattributed", s.Human, s.Attribution.Method)
	}

	mapped := runIngest(t, Options{AppHumans: map[string]string{"deployer[bot]": "alice@example.com"}}, input)
	s := mapped.Sessions[0]
	if s.Human != "alice@example.com" {
		t.Errorf("Human = %q, want the mapped human", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrGitHubApp {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrGitHubApp)
	}
}

func TestIngest_MappedBotStampsPerEventIdentity(t *testing.T) {
	t.Parallel()
	// The installation mapping is deterministic per event (the actor login
	// is on every entry), so a mapped bot's records carry the human as
	// per-event SourceIdentity — the GitHub analogue of STS SourceIdentity,
	// and what de-escalates its production writes under the hybrid rule.
	input := auditEntry("doc-1", "git.push", "deployer[bot]", "r1", t0) + "\n"

	unmapped := runIngest(t, Options{}, input)
	if got := unmapped.Records[0].SourceIdentity; got != "" {
		t.Errorf("unmapped bot record SourceIdentity = %q, want empty", got)
	}

	mapped := runIngest(t, Options{AppHumans: map[string]string{"deployer[bot]": "alice@example.com"}}, input)
	if got := mapped.Records[0].SourceIdentity; got != "alice@example.com" {
		t.Errorf("mapped bot record SourceIdentity = %q, want alice@example.com", got)
	}

	// Human actors self-identify at the session level (actor-identity);
	// their records carry no SourceIdentity — the actor IS the principal.
	human := runIngest(t, Options{}, auditEntry("doc-2", "git.push", "mira-chen", "r1", t0)+"\n")
	if got := human.Records[0].SourceIdentity; got != "" {
		t.Errorf("human actor record SourceIdentity = %q, want empty", got)
	}
}

func TestIngest_GhostAndOrgActorsNotHuman(t *testing.T) {
	t.Parallel()
	// GitHub's "ghost" sentinel (deleted/unattributable user) and the org
	// login appearing as its own actor must not bind as named humans —
	// both observed in a real org audit log.
	for _, actor := range []string{"ghost", "crossbearing"} {
		res := runIngest(t, Options{Org: "crossbearing"},
			auditEntry("doc-1", "billing.budget_create", actor, "", t0)+"\n")
		if s := res.Sessions[0]; s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
			t.Errorf("actor %q bound as human=%q via %q, want unattributed", actor, s.Human, s.Attribution.Method)
		}
	}
}

func TestIngest_ExplicitBotListOverridesHumanHeuristic(t *testing.T) {
	t.Parallel()
	// A machine user with a plain login must not bind to itself.
	res := runIngest(t, Options{Bots: []string{"ci-machine"}},
		auditEntry("doc-1", "git.push", "ci-machine", "r1", t0)+"\n")
	s := res.Sessions[0]
	if s.Human != "" || s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("machine user bound to itself: Human=%q Method=%q", s.Human, s.Attribution.Method)
	}
}

func TestIngest_GapSplitsSessions(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{SessionGap: 30 * time.Minute},
		auditEntry("doc-1", "git.push", "stxkxs", "r1", t0)+"\n"+
			auditEntry("doc-2", "git.push", "stxkxs", "r1", t0.Add(2*time.Hour))+"\n")
	if len(res.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 across a 2h gap", len(res.Sessions))
	}
	if res.Sessions[0].ID == res.Sessions[1].ID {
		t.Error("split sessions share an ID")
	}
}

func TestIngest_ProductionScope(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{IsProduction: func(target string) bool { return target == "crossbearing/prod-deploy" }},
		auditEntry("doc-1", "git.push", "stxkxs", "crossbearing/prod-deploy", t0)+"\n"+
			auditEntry("doc-2", "git.push", "stxkxs", "crossbearing/sandbox", t0)+"\n")
	if !res.Records[0].ProductionTouching || res.Records[1].ProductionTouching {
		t.Errorf("production scoping wrong: %v / %v", res.Records[0].ProductionTouching, res.Records[1].ProductionTouching)
	}
}

func TestIngest_MalformedAndIncompleteEntries(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{},
		"{not json\n"+
			`{"_document_id":"doc-x","action":"repo.create"}`+"\n"+ // no actor
			auditEntry("doc-1", "repo.create", "stxkxs", "r1", t0)+"\n")
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 (malformed and incomplete skipped, rest ingested)", len(res.Records))
	}
}

func TestIngest_EmptyInput(t *testing.T) {
	t.Parallel()
	res := runIngest(t, Options{}, "")
	if len(res.Records) != 0 || len(res.Sessions) != 0 {
		t.Fatalf("empty input produced %d records, %d sessions", len(res.Records), len(res.Sessions))
	}
}
