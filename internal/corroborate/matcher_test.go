package corroborate

import (
	"strings"
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

// The agent's OWN production actions are the same shape as a stranger's, so the
// engine will not corroborate them on a coincidence — it corroborates them when
// the OPERATOR asserts which principal is the agent's (MatchPolicy.AgentRecord,
// wired from --principal). That assertion is an input, like --production-match,
// not a guess the engine makes.
func TestJoin_AgentsOwnProductionAction(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	claims := []Claim{{
		ID: "c1", SessionID: "agent",
		Operation: "Bash(aws s3api delete-bucket --bucket prod-payments)",
		Target:    "aws s3api delete-bucket --bucket prod-payments",
		ClaimedAt: t0, CompletedAt: t0,
	}}
	records := []Record{{
		ID: "ct", Operation: "s3:DeleteBucket",
		Principal:          "arn:aws:sts::1:assumed-role/agent/bot",
		ProductionTouching: true,
		Targets:            []string{"arn:aws:s3:::prod-payments"},
		RecordedAt:         t0.Add(30 * time.Second),
	}}
	om := DeriveOperationMap(claims)

	// Unscoped: the engine cannot tell this record from a stranger's, so it
	// refuses to corroborate — the safe direction, not the convenient one.
	unscoped := Join(sessions, claims, records, MatchPolicy{Window: 20 * time.Minute, OperationMap: om})
	if n := unscoped.Tally()[Corroborated]; n != 0 {
		t.Errorf("unscoped corroborated = %d, want 0 — the engine must not credit a production record it cannot prove is the agent's", n)
	}
	if n := unscoped.Tally()[Unattributed]; n != 1 {
		t.Errorf("unscoped unattributed = %d, want 1", n)
	}

	// Scoped: the operator asserts `agent/bot` is the agent, and the same record
	// now corroborates.
	scoped := Join(sessions, claims, records, MatchPolicy{
		Window: 20 * time.Minute, OperationMap: om,
		AgentRecord: func(r Record) bool { return strings.Contains(r.Principal, "agent/bot") },
	})
	if n := scoped.Tally()[Corroborated]; n != 1 {
		t.Fatalf("scoped corroborated = %d, want 1 — the operator asserted the principal; findings: %+v", n, scoped.Findings)
	}
	if n := scoped.Tally()[Unattributed]; n != 0 {
		t.Errorf("scoped unattributed = %d, want 0", n)
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

// The attacks a fresh adversarial review found against the FIRST attempt at this
// guard, which tried to prove the agent's credential from a coincidental match.
// They must stay dead: each erases a stranger's production action into a false
// corroboration, the one verdict this engine cannot reach.
func TestJoin_CoincidenceNeverProvesTheAgent(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}

	// Attack 1 — the bootstrap. The agent claims a harmless list AND a deletion.
	// A stranger did both, under one key. The read must not "prove" the
	// stranger's credential and thereby unlock crediting them with the deletion.
	t.Run("read does not launder a stranger's credential", func(t *testing.T) {
		t.Parallel()
		claims := []Claim{
			{ID: "c1", SessionID: "agent", Operation: "Bash(aws s3api list-buckets)", Target: "aws s3api list-buckets", ClaimedAt: t0, CompletedAt: t0},
			{ID: "c2", SessionID: "agent", Operation: "Bash(aws s3api delete-bucket --bucket prod-x)", Target: "aws s3api delete-bucket --bucket prod-x", ClaimedAt: t0.Add(time.Minute), CompletedAt: t0.Add(time.Minute)},
		}
		records := []Record{
			{ID: "list", Operation: "s3:ListBuckets", Principal: "arn:aws:iam::1:user/dana", AccessKeyID: "AKIASTRANGER", RecordedAt: t0.Add(time.Second)},
			{ID: "del", Operation: "s3:DeleteBucket", Principal: "arn:aws:iam::1:user/dana", AccessKeyID: "AKIASTRANGER", ProductionTouching: true, Targets: []string{"arn:aws:s3:::prod-x"}, RecordedAt: t0.Add(90 * time.Second)},
		}
		rep := Join(sessions, claims, records, MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)})
		if hasCorroboratedRecord(rep, "del") {
			t.Error("the stranger's production deletion was corroborated via a coincidental read")
		}
		if rep.Tally()[Unattributed] != 1 {
			t.Errorf("the stranger's deletion must remain reportable; unattributed = %d, want 1", rep.Tally()[Unattributed])
		}
	})

	// Attack 2 — a self-declared --operator (the weakest binding) binds the
	// SESSION, and must not de-escalate a stranger's in-window production record.
	t.Run("declared operator does not disarm the guard", func(t *testing.T) {
		t.Parallel()
		declared := []Session{{ID: "agent", Human: "alice@x.com", Attribution: Attribution{Method: AttrDeclared}, StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
		claims := []Claim{{ID: "c1", SessionID: "agent", Operation: "Bash(aws s3api delete-bucket --bucket prod-x)", Target: "aws s3api delete-bucket --bucket prod-x", ClaimedAt: t0, CompletedAt: t0}}
		records := []Record{{ID: "del", Operation: "s3:DeleteBucket", Principal: "arn:aws:iam::1:user/dana", AccessKeyID: "AKIASTRANGER", ProductionTouching: true, Targets: []string{"arn:aws:s3:::prod-x"}, RecordedAt: t0.Add(30 * time.Second)}}
		rep := Join(declared, claims, records, MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)})
		if hasCorroboratedRecord(rep, "del") {
			t.Error("a self-declared operator disarmed the guard: the stranger's deletion was corroborated")
		}
	})
}

func hasCorroboratedRecord(rep Report, recordID string) bool {
	for _, f := range rep.Findings {
		if f.Kind == Corroborated && f.Record != nil && f.Record.ID == recordID {
			return true
		}
	}
	return false
}

// The third false-corroboration path an adversarial re-check found: consumable
// trusted ANY non-empty SourceIdentity as "names its human → safe", never
// checking the human was the AGENT'S. A production record naming a stranger — a
// human running kubectl under impersonation, SourceIdentity=bob — was consumed
// as the agent's corroborated work, and bob's finding erased. Every earlier
// regression used SourceIdentity=="" strangers, so this branch went untested.
func TestJoin_StrangerSourceIdentityIsNotTheAgent(t *testing.T) {
	t.Parallel()
	sessions := []Session{{ID: "agent", StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
	// bob deleted a production secret under impersonation; the record names bob.
	bobDelete := Record{
		ID: "bob-del", Operation: "k8s-audit:delete:secrets",
		Principal: "system:serviceaccount:agents:sa", SourceIdentity: "bob@corp",
		ProductionTouching: true, Targets: []string{"monitoring/secrets/grafana-admin"},
		RecordedAt: t0.Add(30 * time.Second),
	}

	t.Run("phantom claim cannot corroborate a stranger's named record", func(t *testing.T) {
		t.Parallel()
		claims := []Claim{{ID: "phantom", SessionID: "agent",
			Operation: "Bash(kubectl delete secret grafana-admin -n monitoring)",
			Target:    "kubectl delete secret grafana-admin -n monitoring",
			ClaimedAt: t0, CompletedAt: t0}}
		rep := Join(sessions, claims, []Record{bobDelete}, MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)})
		if hasCorroboratedRecord(rep, "bob-del") {
			t.Error("bob's production deletion corroborated as the agent's work")
		}
	})

	t.Run("honest claim cannot steal a stranger's named record as a Mismatch", func(t *testing.T) {
		t.Parallel()
		claims := []Claim{{ID: "reader", SessionID: "agent",
			Operation: "Bash(kubectl get pods -n monitoring)", Target: "kubectl get pods -n monitoring",
			ClaimedAt: t0, CompletedAt: t0}}
		rep := Join(sessions, claims, []Record{bobDelete}, MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)})
		for _, f := range rep.Findings {
			if f.Kind == Mismatch && f.Record != nil && f.Record.ID == "bob-del" {
				t.Error("bob's deletion stolen as a Mismatch against the agent")
			}
		}
	})

	// The agent's OWN impersonation record — SourceIdentity == the session's bound
	// human — is the agent's, and must still corroborate.
	t.Run("the agent's own impersonation record still corroborates", func(t *testing.T) {
		t.Parallel()
		bound := []Session{{ID: "agent", Human: "alice@corp", Attribution: Attribution{Method: AttrK8sImpersonation}, StartedAt: t0, EndedAt: t0.Add(time.Hour)}}
		claims := []Claim{{ID: "c1", SessionID: "agent",
			Operation: "Bash(kubectl delete deploy api -n prod)", Target: "kubectl delete deploy api -n prod",
			ClaimedAt: t0, CompletedAt: t0}}
		records := []Record{{ID: "r1", Operation: "k8s-audit:delete:deployments",
			Principal: "system:serviceaccount:agents:sa", SourceIdentity: "alice@corp",
			ProductionTouching: true, Targets: []string{"prod/deployments/api"}, RecordedAt: t0.Add(20 * time.Second)}}
		rep := Join(bound, claims, records, MatchPolicy{Window: 20 * time.Minute, OperationMap: DeriveOperationMap(claims)})
		if n := rep.Tally()[Corroborated]; n != 1 {
			t.Errorf("the agent's own impersonation record must corroborate; corroborated=%d", n)
		}
	})
}
