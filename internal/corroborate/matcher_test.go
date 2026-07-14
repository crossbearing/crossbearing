package corroborate

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

func session(id, human string) Session {
	s := Session{
		ID: id, Agent: "claude-code",
		StartedAt: t0, EndedAt: t0.Add(time.Hour),
	}
	if human != "" {
		s.Human = human
		s.Attribution = Attribution{Method: AttrSTSSourceIdentity}
	} else {
		s.Attribution = Attribution{Method: AttrNone}
	}
	return s
}

func TestJoin_CorroboratedClaim(t *testing.T) {
	sessions := []Session{session("s1", "alice")}
	claims := []Claim{{ID: "c1", SessionID: "s1", Source: SourceClaudeCodeTelemetry,
		Operation: "PutObject", Target: "bucket/key", ClaimedAt: t0.Add(5 * time.Minute)}}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "PutObject",
		Principal: "arn:aws:sts::1:assumed-role/agents/alice", SourceIdentity: "alice",
		RecordedAt: t0.Add(9 * time.Minute)}}

	rep := Join(sessions, claims, records, DefaultMatchPolicy())
	if n := rep.Tally()[Corroborated]; n != 1 {
		t.Fatalf("Corroborated = %d, want 1; findings: %+v", n, rep.Findings)
	}
	f := rep.Findings[0]
	if f.Claim == nil || f.Record == nil || f.Claim.ID != "c1" || f.Record.ID != "r1" {
		t.Errorf("corroborated finding should join c1 with r1, got %+v", f)
	}
}

func TestJoin_MismatchWhenOperationsDisagree(t *testing.T) {
	sessions := []Session{session("s1", "alice")}
	claims := []Claim{{ID: "c1", SessionID: "s1", Operation: "GetObject",
		ClaimedAt: t0.Add(5 * time.Minute)}}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "PutBucketPolicy",
		RecordedAt: t0.Add(6 * time.Minute)}}

	rep := Join(sessions, claims, records, DefaultMatchPolicy())
	if n := rep.Tally()[Mismatch]; n != 1 {
		t.Fatalf("Mismatch = %d, want 1; findings: %+v", n, rep.Findings)
	}
	if why := rep.Findings[0].Why; why == "" {
		t.Error("mismatch finding must carry an operator-readable Why")
	}
}

func TestJoin_UnrecordedClaim(t *testing.T) {
	sessions := []Session{session("s1", "alice")}
	claims := []Claim{{ID: "c1", SessionID: "s1", Operation: "DeleteObject",
		ClaimedAt: t0.Add(5 * time.Minute)}}

	rep := Join(sessions, claims, nil, DefaultMatchPolicy())
	if n := rep.Tally()[UnrecordedClaim]; n != 1 {
		t.Fatalf("UnrecordedClaim = %d, want 1", n)
	}
}

func TestJoin_UnclaimedRecordInsideWindow(t *testing.T) {
	sessions := []Session{session("s1", "alice")}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "RunInstances",
		RecordedAt: t0.Add(30 * time.Minute)}}

	rep := Join(sessions, nil, records, DefaultMatchPolicy())
	if n := rep.Tally()[UnclaimedRecord]; n != 1 {
		t.Fatalf("UnclaimedRecord = %d, want 1; findings: %+v", n, rep.Findings)
	}
}

func TestJoin_UnattributedEscalation(t *testing.T) {
	// Unattributed session + production-touching unclaimed record = the
	// demo's headline finding.
	sessions := []Session{session("s1", "")}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "ModifyDBInstance",
		ProductionTouching: true, RecordedAt: t0.Add(10 * time.Minute)}}

	rep := Join(sessions, nil, records, DefaultMatchPolicy())
	if n := rep.Tally()[Unattributed]; n != 1 {
		t.Fatalf("Unattributed = %d, want 1; findings: %+v", n, rep.Findings)
	}
}

func TestJoin_RecordCarriedIdentityDeEscalates(t *testing.T) {
	// A record that itself names its human (per-event SourceIdentity — the
	// strongest binding there is) is accountable: it stays unclaimed, never
	// unattributed, even when the agent session declared no operator.
	sessions := []Session{session("s1", "")}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "ModifyDBInstance",
		ProductionTouching: true, SourceIdentity: "priya@example.com",
		RecordedAt: t0.Add(10 * time.Minute)}}

	rep := Join(sessions, nil, records, DefaultMatchPolicy())
	if n := rep.Tally()[Unattributed]; n != 0 {
		t.Fatalf("Unattributed = %d, want 0 (record names its human); findings: %+v", n, rep.Findings)
	}
	if n := rep.Tally()[UnclaimedRecord]; n != 1 {
		t.Fatalf("UnclaimedRecord = %d, want 1; findings: %+v", n, rep.Findings)
	}
}

func TestJoin_RecordOutsideAnyWindowIgnoredWithoutFingerprint(t *testing.T) {
	sessions := []Session{session("s1", "alice")}
	records := []Record{{ID: "r1", Source: SourceCloudTrail, Operation: "PutObject",
		RecordedAt: t0.Add(6 * time.Hour)}} // far outside, no SourceIdentity

	rep := Join(sessions, nil, records, DefaultMatchPolicy())
	if len(rep.Findings) != 0 {
		t.Fatalf("expected human activity to be out of scope, got %+v", rep.Findings)
	}
}

func TestJoin_OperationMapTranslatesVocabulary(t *testing.T) {
	p := DefaultMatchPolicy()
	p.OperationMap = map[string][]string{
		"mcp:create_pull_request": {"pull_request.create"},
	}
	sessions := []Session{session("s1", "alice")}
	claims := []Claim{{ID: "c1", SessionID: "s1", Source: SourceAgentReceipt,
		Operation: "mcp:create_pull_request", ClaimedAt: t0.Add(5 * time.Minute)}}
	records := []Record{{ID: "r1", Source: SourceGitHubAudit, Operation: "pull_request.create",
		RecordedAt: t0.Add(5 * time.Minute)}}

	rep := Join(sessions, claims, records, p)
	if n := rep.Tally()[Corroborated]; n != 1 {
		t.Fatalf("Corroborated = %d, want 1 (operation map should translate); findings: %+v", n, rep.Findings)
	}
}

func TestJoin_PrefersOperationAgreementOverProximity(t *testing.T) {
	// A closer-in-time record with the WRONG operation must not steal the
	// match from a farther record with the RIGHT operation.
	sessions := []Session{session("s1", "alice")}
	claims := []Claim{{ID: "c1", SessionID: "s1", Operation: "PutObject",
		ClaimedAt: t0.Add(5 * time.Minute)}}
	records := []Record{
		{ID: "near-wrong", Operation: "DeleteObject", RecordedAt: t0.Add(5 * time.Minute)},
		{ID: "far-right", Operation: "PutObject", RecordedAt: t0.Add(15 * time.Minute)},
	}

	rep := Join(sessions, claims, records, DefaultMatchPolicy())
	for _, f := range rep.Findings {
		if f.Kind == Corroborated {
			if f.Record.ID != "far-right" {
				t.Fatalf("matched %s, want far-right", f.Record.ID)
			}
			return
		}
	}
	t.Fatalf("no corroborated finding produced: %+v", rep.Findings)
}

// Every claim split out of one shell script carries that tool call's
// ClaimedAt, so a script's commands are equal keys in the sort — and their
// input order IS their execution order. An unstable sort permutes them, and
// because bestRecord greedily consumes records, a later command's claim can
// then be credited with an earlier one's record.
//
// The counts stay right and the evidence goes quietly wrong. That claim→record
// pairing is precisely what the hash chain signs.
func TestJoin_SameTimestampClaimsKeepExecutionOrder(t *testing.T) {
	t.Parallel()
	// Two identical commands from one script: same op, same ClaimedAt. Only
	// their order distinguishes which record belongs to which.
	at := t0
	sessions := []Session{{ID: "s", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	claims := []Claim{
		{ID: "toolu#0", SessionID: "s", Operation: "Bash(kubectl get pods)", Target: "kubectl get pods",
			ClaimedAt: at, CompletedAt: at.Add(5 * time.Minute)},
		{ID: "toolu#1", SessionID: "s", Operation: "Bash(kubectl get pods)", Target: "kubectl get pods",
			ClaimedAt: at, CompletedAt: at.Add(5 * time.Minute)},
	}
	records := []Record{
		{ID: "first", Operation: "k8s-audit:get:pods", RecordedAt: at.Add(1 * time.Minute)},
		{ID: "second", Operation: "k8s-audit:get:pods", RecordedAt: at.Add(4 * time.Minute)},
	}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)

	got := map[string]string{}
	for _, f := range rep.Findings {
		if f.Kind == Corroborated {
			got[f.Claim.ID] = f.Record.ID
		}
	}
	if len(got) != 2 {
		t.Fatalf("corroborated = %d, want 2: %+v", len(got), rep.Findings)
	}
	// The first command in the script gets the first record. Anything else is
	// evidence that names the wrong record for the wrong command.
	if got["toolu#0"] != "first" || got["toolu#1"] != "second" {
		t.Errorf("claim→record pairing = %v, want toolu#0→first, toolu#1→second", got)
	}
}

// A shell claim is not an instant. Agent scripts sleep and wait on rollouts —
// the dev-eks corpus has `sleep 90` and `rollout status --timeout=150s` inside
// single tool calls — and every command split out of one inherits that call's
// start time. Matched as a point, a long script's later commands fall outside
// the window: the claim becomes UnrecordedClaim and its record becomes
// UnclaimedRecord, both false, and both the exact pair the engine exists to
// avoid inventing.
func TestJoin_LongRunningScriptStillCorroborates(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "s", StartedAt: t0, EndedAt: t0.Add(2 * time.Hour)}}
	// The tool call starts at t0 and returns 45 minutes later; the command it
	// ran landed 40 minutes in — far outside a 20-minute window measured from
	// ClaimedAt, but well inside the span in which the call was running.
	claims := []Claim{{
		ID: "toolu#0", SessionID: "s",
		Operation: "Bash(kubectl -n prod delete deploy/api)", Target: "kubectl -n prod delete deploy/api",
		ClaimedAt: t0, CompletedAt: t0.Add(45 * time.Minute),
	}}
	records := []Record{{
		ID: "rec-1", Operation: "k8s-audit:delete:deployments", RecordedAt: t0.Add(40 * time.Minute),
	}}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)

	if n := rep.Tally()[Corroborated]; n != 1 {
		t.Fatalf("corroborated = %d, want 1 — the record landed while the tool call was still running; findings: %+v", n, rep.Findings)
	}
	if n := rep.Tally()[UnrecordedClaim] + rep.Tally()[UnclaimedRecord]; n != 0 {
		t.Errorf("invented %d false finding(s) for work that plainly corroborates", n)
	}
}

// A claim stream that reports no completion time degrades to the old point
// behaviour exactly — no widening, no surprise matches.
func TestJoin_NoCompletedAtIsPointMatchedAsBefore(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "s", StartedAt: t0, EndedAt: t0.Add(2 * time.Hour)}}
	claims := []Claim{{
		ID: "c1", SessionID: "s",
		Operation: "Bash(kubectl -n prod delete deploy/api)", Target: "kubectl -n prod delete deploy/api",
		ClaimedAt: t0, // CompletedAt deliberately zero
	}}
	records := []Record{{
		ID: "rec-1", Operation: "k8s-audit:delete:deployments", RecordedAt: t0.Add(40 * time.Minute),
	}}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)
	if n := rep.Tally()[Corroborated]; n != 0 {
		t.Errorf("corroborated = %d, want 0 — with no completion time the claim is a point and the record is 40m away", n)
	}
}

// THE catastrophic case, and the reason the join is identity-aware.
//
// An agent writes a deploy script with a heredoc. It never runs the deletion the
// script names. In the same window a HUMAN deletes that production bucket. With
// the join correlating on time and operation alone, the human's record was
// consumed as Corroborated — the agent was credited with an action it never
// performed, and the human's unattributed production deletion VANISHED from the
// report. A report that affirmatively denies a divergence is the worst verdict
// this engine can reach.
func TestJoin_ForeignRecordIsNeverCorroborated(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	claims := []Claim{{
		ID: "toolu_1", SessionID: "agent",
		Operation: "Bash(aws s3api delete-bucket --bucket prod-payments)",
		Target:    "aws s3api delete-bucket --bucket prod-payments",
		ClaimedAt: t0, CompletedAt: t0.Add(time.Second),
	}}
	records := []Record{{
		ID: "ct-human", Operation: "s3:DeleteBucket",
		Principal:          "arn:aws:iam::111122223333:user/dana", // a person, not the agent
		AccessKeyID:        "AKIAHUMANKEY",
		Targets:            []string{"arn:aws:s3:::prod-payments"},
		ProductionTouching: true,
		RecordedAt:         t0.Add(3 * time.Minute),
	}}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)

	if n := rep.Tally()[Corroborated]; n != 0 {
		t.Errorf("corroborated = %d, want 0 — a stranger's production deletion was credited to the agent", n)
	}
	if n := rep.Tally()[Unattributed]; n != 1 {
		t.Errorf("unattributed = %d, want 1 — the human's production deletion must still be reported", n)
	}
	if n := rep.Tally()[UnrecordedClaim]; n != 1 {
		t.Errorf("unrecordedClaim = %d, want 1 — the agent's claim has no record of its own", n)
	}
}

// The agent's OWN production actions are the same shape as a stranger's — and
// they must still corroborate. The credential is proved without circularity: a
// non-escalating corroboration (a read, a non-production write) shows which
// credential the agent holds, and only then may it be credited with the actions
// that would otherwise be unattributed.
func TestJoin_AgentsOwnProductionActionCorroborates(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	claims := []Claim{
		// A harmless read: proves the credential is the agent's.
		{ID: "c1", SessionID: "agent", Operation: "Bash(aws sts get-caller-identity)",
			Target: "aws sts get-caller-identity", ClaimedAt: t0, CompletedAt: t0},
		// A production write under the SAME credential.
		{ID: "c2", SessionID: "agent", Operation: "Bash(aws s3api delete-bucket --bucket prod-payments)",
			Target: "aws s3api delete-bucket --bucket prod-payments", ClaimedAt: t0.Add(time.Minute), CompletedAt: t0.Add(time.Minute)},
	}
	records := []Record{
		{ID: "ct-1", Operation: "sts:GetCallerIdentity", AccessKeyID: "ASIAAGENTKEY",
			Principal: "arn:aws:sts::1:assumed-role/agent/bot", RecordedAt: t0.Add(2 * time.Second)},
		{ID: "ct-2", Operation: "s3:DeleteBucket", AccessKeyID: "ASIAAGENTKEY",
			Principal: "arn:aws:sts::1:assumed-role/agent/bot", ProductionTouching: true,
			Targets: []string{"arn:aws:s3:::prod-payments"}, RecordedAt: t0.Add(70 * time.Second)},
	}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)

	if n := rep.Tally()[Corroborated]; n != 2 {
		t.Fatalf("corroborated = %d, want 2 — the agent's own production action must corroborate once its credential is proved; findings: %+v", n, rep.Findings)
	}
	if n := rep.Tally()[Unattributed]; n != 0 {
		t.Errorf("unattributed = %d, want 0 — the record IS the agent's, proved by ct-1's shared credential", n)
	}
}

// A claim whose true record is momentarily out of reach must not STEAL an
// unrelated one and report it as a Mismatch — that invents a divergence out of
// two unrelated facts. Mismatches are matched last, after every agreeing pair
// has been settled.
func TestJoin_MismatchNeverStealsAnAgreeingRecord(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	claims := []Claim{
		{ID: "reader", SessionID: "agent", Operation: "Bash(aws s3api get-bucket-policy --bucket prod-x)",
			Target: "aws s3api get-bucket-policy --bucket prod-x", ClaimedAt: t0, CompletedAt: t0},
		{ID: "lister", SessionID: "agent", Operation: "Bash(aws iam list-access-keys)",
			Target: "aws iam list-access-keys", ClaimedAt: t0.Add(time.Minute), CompletedAt: t0.Add(time.Minute)},
	}
	records := []Record{
		// Nothing agrees with `reader`. It must NOT take the lister's record.
		{ID: "ct-keys", Operation: "iam:ListAccessKeys", AccessKeyID: "K", RecordedAt: t0.Add(30 * time.Second)},
	}
	p := MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)}

	rep := Join(sessions, claims, records, p)

	for _, f := range rep.Findings {
		if f.Kind == Mismatch && f.Claim.ID == "reader" {
			t.Errorf("the reader claim stole %s and reported a Mismatch; the record belongs to the lister", f.Record.ID)
		}
		if f.Kind == Corroborated && f.Claim.ID != "lister" {
			t.Errorf("ct-keys corroborated the wrong claim: %s", f.Claim.ID)
		}
	}
	if n := rep.Tally()[Corroborated]; n != 1 {
		t.Errorf("corroborated = %d, want 1 (the lister)", n)
	}
}
