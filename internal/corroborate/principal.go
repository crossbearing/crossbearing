package corroborate

import "strings"

// A Record.Principal is stream-specific: a GitHub actor, a K8s username, or —
// for the AWS streams — an STS ARN. These helpers parse the assumed-role ARN
// shape (arn:…:assumed-role/ROLE/SESSION) and are the single source of that
// parsing; the cloudtrail ingester, the cmd convention check, and agent-suspect
// scoping all delegate here so the three never drift. Both return "" for any
// principal that is not an assumed-role ARN.

const assumedRoleMarker = ":assumed-role/"

// RoleNameFromARN returns ROLE from arn:…:assumed-role/ROLE/SESSION.
func RoleNameFromARN(principal string) string {
	rest, ok := afterAssumedRole(principal)
	if !ok {
		return ""
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// SessionNameFromARN returns SESSION from arn:…:assumed-role/ROLE/SESSION.
func SessionNameFromARN(principal string) string {
	rest, ok := afterAssumedRole(principal)
	if !ok {
		return ""
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j+1:]
	}
	return ""
}

func afterAssumedRole(principal string) (string, bool) {
	i := strings.Index(principal, assumedRoleMarker)
	if i < 0 {
		return "", false
	}
	return principal[i+len(assumedRoleMarker):], true
}
