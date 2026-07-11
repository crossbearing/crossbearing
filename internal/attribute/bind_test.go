package attribute

import (
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

var t0 = time.Date(2026, 6, 10, 3, 0, 0, 0, time.UTC)

const (
	claimSID   = "f0b7fa2e-26e4-4fa7-ad56-66c4c66623f0"
	principal  = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin/sysadmin"
	agentRSID  = principal + "@2026-06-10T02:50:00Z/ASIAAGENTKEY"
	otherRSID  = principal + "@2026-06-10T04:30:00Z/ASIAOTHERKEY"
	roleARNStr = "arn:aws:iam::111122223333:role/AWSReservedSSO_Admin"
)

func claimSession(human string) corroborate.Session {
	s := corroborate.Session{
		ID: claimSID, Agent: "claude-code",
		StartedAt: t0.Add(-10 * time.Minute), EndedAt: t0.Add(2 * time.Hour),
	}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrDeclared, Evidence: []string{"claude-code:/t.jsonl"}}
	}
	return s
}

func recordSession(id, human string, method corroborate.AttributionMethod, start time.Time) corroborate.Session {
	s := corroborate.Session{ID: id, Agent: "sysadmin", StartedAt: start, EndedAt: start.Add(30 * time.Minute)}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{Method: method, Evidence: []string{"evt-src"}}
	}
	return s
}

func corroboratedFinding(recordID, accessKey string) corroborate.Finding {
	return corroborate.Finding{
		Kind: corroborate.Corroborated, SessionID: claimSID,
		Record: &corroborate.Record{ID: recordID, AccessKeyID: accessKey},
	}
}

func TestBind_CorroboratedAccessKey(t *testing.T) {
	t.Parallel()
	got := Bind(
		[]corroborate.Session{claimSession("operator@example.com")},
		[]corroborate.Session{recordSession(agentRSID, "", corroborate.AttrNone, t0)},
		[]corroborate.Finding{
			corroboratedFinding("evt-1", "ASIAAGENTKEY"),
			corroboratedFinding("evt-2", "ASIAAGENTKEY"),
		},
	)

	if len(got) != 1 {
		t.Fatalf("bindings = %d, want 1", len(got))
	}
	b := got[0]
	if b.Confidence != ConfidenceCorroborated {
		t.Errorf("Confidence = %q, want %q", b.Confidence, ConfidenceCorroborated)
	}
	if b.ClaimSessionID != claimSID || b.RecordSessionID != agentRSID {
		t.Errorf("bound %q ⇄ %q", b.ClaimSessionID, b.RecordSessionID)
	}
	if b.Principal != principal {
		t.Errorf("Principal = %q, want %q", b.Principal, principal)
	}
	if len(b.Evidence) != 2 || b.Evidence[0] != "evt-1" {
		t.Errorf("Evidence = %v, want the corroborating record IDs", b.Evidence)
	}
	// Record side is unattributed; the declared operator carries through.
	if b.Human != "operator@example.com" || b.Method != corroborate.AttrDeclared {
		t.Errorf("Human = %q via %q, want declared operator", b.Human, b.Method)
	}
}

func TestBind_OverlapOnlyIsWeak(t *testing.T) {
	t.Parallel()
	// The other actor's session: same principal, different key, no
	// corroborated claims — it merely shares the wall clock.
	got := Bind(
		[]corroborate.Session{claimSession("operator@example.com")},
		[]corroborate.Session{recordSession(otherRSID, "", corroborate.AttrNone, t0.Add(90*time.Minute))},
		nil,
	)
	if len(got) != 1 {
		t.Fatalf("bindings = %d, want 1", len(got))
	}
	if got[0].Confidence != ConfidenceOverlap {
		t.Errorf("Confidence = %q, want %q", got[0].Confidence, ConfidenceOverlap)
	}
}

func TestBind_RecordHumanOutranksDeclared(t *testing.T) {
	t.Parallel()
	got := Bind(
		[]corroborate.Session{claimSession("operator@example.com")},
		[]corroborate.Session{recordSession(agentRSID, "operator@example.com", corroborate.AttrSTSSourceIdentity, t0)},
		[]corroborate.Finding{corroboratedFinding("evt-1", "ASIAAGENTKEY")},
	)
	b := got[0]
	if b.Method != corroborate.AttrSTSSourceIdentity {
		t.Errorf("Method = %q, want record-side sts-source-identity to outrank declared", b.Method)
	}
	if b.Conflict != "" {
		t.Errorf("Conflict = %q, want none when both sides agree", b.Conflict)
	}
}

func TestBind_ConflictSurfacedNotResolved(t *testing.T) {
	t.Parallel()
	got := Bind(
		[]corroborate.Session{claimSession("mallory@example.com")},
		[]corroborate.Session{recordSession(agentRSID, "bs@example.com", corroborate.AttrSTSSourceIdentity, t0)},
		[]corroborate.Finding{corroboratedFinding("evt-1", "ASIAAGENTKEY")},
	)
	b := got[0]
	if b.Human != "bs@example.com" {
		t.Errorf("Human = %q, want the record-side identity", b.Human)
	}
	if b.Conflict == "" {
		t.Error("Conflict empty; a declared/recorded disagreement must be surfaced")
	}
}

func TestBind_NoOverlapNoBinding(t *testing.T) {
	t.Parallel()
	got := Bind(
		[]corroborate.Session{claimSession("")},
		[]corroborate.Session{recordSession(principal+"@2026-06-09T01:00:00Z/ASIAOLD", "", corroborate.AttrNone, t0.Add(-26*time.Hour))},
		nil,
	)
	if len(got) != 0 {
		t.Fatalf("bindings = %d, want 0 for disjoint windows", len(got))
	}
}

func TestBind_UnattributedBothSides(t *testing.T) {
	t.Parallel()
	got := Bind(
		[]corroborate.Session{claimSession("")},
		[]corroborate.Session{recordSession(agentRSID, "", corroborate.AttrNone, t0)},
		[]corroborate.Finding{corroboratedFinding("evt-1", "ASIAAGENTKEY")},
	)
	if got[0].Human != "" || got[0].Method != corroborate.AttrNone {
		t.Errorf("got Human=%q Method=%q, want unattributed", got[0].Human, got[0].Method)
	}
}

func TestSplitRecordSessionID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id, wantPrincipal, wantKey string
	}{
		{agentRSID, principal, "ASIAAGENTKEY"},
		{principal + "@2026-06-10T02:50:00Z", principal, ""},
		{"no-at-sign", "no-at-sign", ""},
	}
	for _, tt := range tests {
		p, k := splitRecordSessionID(tt.id)
		if p != tt.wantPrincipal || k != tt.wantKey {
			t.Errorf("splitRecordSessionID(%q) = (%q, %q), want (%q, %q)", tt.id, p, k, tt.wantPrincipal, tt.wantKey)
		}
	}
}
