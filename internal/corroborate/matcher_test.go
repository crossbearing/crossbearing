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
