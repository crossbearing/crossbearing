package attribute

import (
	"strings"
	"testing"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

const (
	agentARN   = "arn:aws:sts::111122223333:assumed-role/agent-deployer/deploy-bot"
	slrARN     = "arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSSM/i-0abc123"
	iamUserARN = "arn:aws:iam::111122223333:user/ci"
)

func TestProvenKeys(t *testing.T) {
	findings := []corroborate.Finding{
		// corroborated with a key → proves the key
		{Kind: corroborate.Corroborated, SessionID: "sess-a", Record: &corroborate.Record{ID: "ct-1", AccessKeyID: "ASIAAGENT0001"}},
		// another corroborated record on the same key, same session → adds evidence
		{Kind: corroborate.Corroborated, SessionID: "sess-a", Record: &corroborate.Record{ID: "ct-9", AccessKeyID: "ASIAAGENT0001"}},
		// corroborated but no key → ignored
		{Kind: corroborate.Corroborated, SessionID: "sess-a", Record: &corroborate.Record{ID: "k8s-1"}},
		// not corroborated → ignored even with a key
		{Kind: corroborate.Unattributed, SessionID: "sess-a", Record: &corroborate.Record{ID: "ct-2", AccessKeyID: "ASIAAGENT0001"}},
		// a different proven key, different session
		{Kind: corroborate.Corroborated, SessionID: "sess-b", Record: &corroborate.Record{ID: "ct-3", AccessKeyID: "ASIAOTHER0002"}},
	}
	pk := ProvenKeys(findings)
	if len(pk) != 2 {
		t.Fatalf("proven keys = %d, want 2: %v", len(pk), pk)
	}
	a := pk["ASIAAGENT0001"]
	if a.ClaimSessionID != "sess-a" {
		t.Errorf("ASIAAGENT0001 claim session = %q, want sess-a", a.ClaimSessionID)
	}
	if got := strings.Join(a.RecordIDs, ","); got != "ct-1,ct-9" {
		t.Errorf("ASIAAGENT0001 record ids = %q, want ct-1,ct-9", got)
	}
	if pk["ASIAOTHER0002"].ClaimSessionID != "sess-b" {
		t.Errorf("ASIAOTHER0002 claim session = %q, want sess-b", pk["ASIAOTHER0002"].ClaimSessionID)
	}
}

func TestProvenKeys_keyProvenByOneSessionOnly(t *testing.T) {
	// A key first proven by sess-a; a later corroborated record on the same key
	// under sess-b must NOT add evidence (mirrors Bind's proofByKey).
	findings := []corroborate.Finding{
		{Kind: corroborate.Corroborated, SessionID: "sess-a", Record: &corroborate.Record{ID: "ct-1", AccessKeyID: "ASIAAGENT0001"}},
		{Kind: corroborate.Corroborated, SessionID: "sess-b", Record: &corroborate.Record{ID: "ct-2", AccessKeyID: "ASIAAGENT0001"}},
	}
	pk := ProvenKeys(findings)["ASIAAGENT0001"]
	if pk.ClaimSessionID != "sess-a" {
		t.Errorf("claim session = %q, want sess-a", pk.ClaimSessionID)
	}
	if got := strings.Join(pk.RecordIDs, ","); got != "ct-1" {
		t.Errorf("record ids = %q, want ct-1 only", got)
	}
}

func TestAgentSuspect(t *testing.T) {
	provenIdx := ScopeIndex{ProvenKeys: map[string]ProvenKey{
		"ASIAAGENT0001": {ClaimSessionID: "sess-a", RecordIDs: []string{"ct-1"}},
	}}
	patternIdx := ScopeIndex{SessionPattern: "deploy-bot"}

	tests := []struct {
		name      string
		rec       corroborate.Record
		idx       ScopeIndex
		wantOK    bool
		reasonHas string
	}{
		{
			name:      "proven credential fires with evidence",
			rec:       corroborate.Record{Principal: agentARN, AccessKeyID: "ASIAAGENT0001"},
			idx:       provenIdx,
			wantOK:    true,
			reasonHas: "corroborated record ct-1",
		},
		{
			name:   "same principal but unproven key → fail-open",
			rec:    corroborate.Record{Principal: agentARN, AccessKeyID: "ASIAUNKNOWN9"},
			idx:    provenIdx,
			wantOK: false,
		},
		{
			name:      "operator pattern matches session name",
			rec:       corroborate.Record{Principal: agentARN},
			idx:       patternIdx,
			wantOK:    true,
			reasonHas: "operator-supplied pattern deploy-bot",
		},
		{
			name:   "operator pattern does not match",
			rec:    corroborate.Record{Principal: "arn:aws:sts::111122223333:assumed-role/other/sess-x"},
			idx:    patternIdx,
			wantOK: false,
		},
		{
			name:   "service-linked role is never suspect, even on a proven key",
			rec:    corroborate.Record{Principal: slrARN, AccessKeyID: "ASIAAGENT0001"},
			idx:    provenIdx,
			wantOK: false,
		},
		{
			name:   "service-linked role is never suspect, even when the pattern matches its session name",
			rec:    corroborate.Record{Principal: slrARN},
			idx:    ScopeIndex{SessionPattern: "i-0abc"},
			wantOK: false,
		},
		{
			name:   "non-assumed-role principal has no session name → not suspect",
			rec:    corroborate.Record{Principal: iamUserARN},
			idx:    patternIdx,
			wantOK: false,
		},
		{
			name:   "no signals at all → fail-open false",
			rec:    corroborate.Record{Principal: agentARN, AccessKeyID: "ASIAUNKNOWN9"},
			idx:    ScopeIndex{},
			wantOK: false,
		},
		{
			name:   "empty record does not panic and is not suspect",
			rec:    corroborate.Record{},
			idx:    provenIdx,
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := AgentSuspect(tc.rec, tc.idx)
			if ok != tc.wantOK {
				t.Fatalf("AgentSuspect ok = %v, want %v (reason %q)", ok, tc.wantOK, reason)
			}
			if ok && tc.reasonHas != "" && !strings.Contains(reason, tc.reasonHas) {
				t.Errorf("reason = %q, want substring %q", reason, tc.reasonHas)
			}
			if !ok && reason != "" {
				t.Errorf("not suspect but got reason %q", reason)
			}
		})
	}
}
