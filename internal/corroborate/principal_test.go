package corroborate

import "testing"

func TestPrincipalARNParsing(t *testing.T) {
	for _, tc := range []struct {
		arn       string
		role, sid string
	}{
		{"arn:aws:sts::111122223333:assumed-role/agent-deployer/deploy-bot", "agent-deployer", "deploy-bot"},
		{"arn:aws:sts::111122223333:assumed-role/AWSServiceRoleForSSM/i-0abc123", "AWSServiceRoleForSSM", "i-0abc123"},
		{"arn:aws:sts::1:assumed-role/role-only", "", ""}, // no session segment
		{"arn:aws:iam::111122223333:user/ci", "", ""},     // not an assumed-role ARN
		{"deploy-bot", "", ""}, // not an ARN at all
		{"", "", ""},           // empty
	} {
		if got := RoleNameFromARN(tc.arn); got != tc.role {
			t.Errorf("RoleNameFromARN(%q) = %q, want %q", tc.arn, got, tc.role)
		}
		if got := SessionNameFromARN(tc.arn); got != tc.sid {
			t.Errorf("SessionNameFromARN(%q) = %q, want %q", tc.arn, got, tc.sid)
		}
	}
}
