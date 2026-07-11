package attribute

import (
	"strings"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Agent-suspect scoping answers a narrower question than attribution does:
// not "who did this" but "is this unattributed record worth the auditor's eye
// as the agent's?". On a real account the in-window unattributed set mixes the
// agent's own actions with same-principal bystander activity (an SSO cache
// hands the same role to humans and agents alike). This classifier surfaces
// the subset we can positively tie to an agent, leaving everything else fully
// visible — a labeling pass, never a filter that removes evidence.
//
// Two rules keep it honest:
//   - It NEVER asserts a human. It returns (bool, reason); Human is still set
//     only by the proven attribution ladder (SourceIdentity / tags / impersonation).
//   - It is FAIL-OPEN. A record is promoted only on a NAMED positive signal;
//     absent one it stays in tier-1. The classifier can add attention, never
//     subtract a record from the complete trail.
//
// The proven-credential signal rests on ProvenKeys (see bind.go) — the same
// evidence Bind uses, so the two cannot drift.

// ScopeIndex holds the precomputed signals AgentSuspect needs for a window.
type ScopeIndex struct {
	// ProvenKeys: access keys a corroborated finding tied to an agent session.
	ProvenKeys map[string]ProvenKey
	// SessionPattern, when non-empty, is an operator-supplied substring that
	// marks an assumed-role session name as the agent's. Operator-asserted
	// scoping, labeled as such — not engine-derived evidence.
	SessionPattern string
}

// NewScopeIndex builds the index from the joined findings and the operator's
// optional --agent-session-pattern.
func NewScopeIndex(findings []corroborate.Finding, sessionPattern string) ScopeIndex {
	return ScopeIndex{ProvenKeys: ProvenKeys(findings), SessionPattern: sessionPattern}
}

// AgentSuspect reports whether an unattributed record carries a positive
// agent fingerprint, with a human-readable reason for any positive so every
// tier-2 promotion is explainable to an auditor. Negative checks run first
// (provably-not-agent can never be promoted); positives run strongest-first.
// Returns false with no reason when nothing fires — the fail-open default.
func AgentSuspect(r corroborate.Record, idx ScopeIndex) (suspect bool, reason string) {
	// Negative: AWS-reserved service-linked roles (SSM, ResourceExplorer, …)
	// are provably not an agent — a customer cannot create these. (AWS-service
	// callers carry no assumed-role ARN, so they match no positive signal and
	// stay tier-1 without a special case.)
	if isServiceLinked(r.Principal) {
		return false, ""
	}

	// 1. Proven credential — evidence, not a heuristic. The access key a
	// corroborated finding tied to the agent's claim session.
	if r.AccessKeyID != "" {
		if pk, ok := idx.ProvenKeys[r.AccessKeyID]; ok {
			by := ""
			if len(pk.RecordIDs) > 0 {
				by = " " + pk.RecordIDs[0]
			}
			return true, "credential session proven to be the agent's by corroborated record" + by
		}
	}

	// 2. Operator-supplied session-name pattern — operator-asserted scoping,
	// never presented as engine-derived evidence.
	if idx.SessionPattern != "" {
		if sn := corroborate.SessionNameFromARN(r.Principal); sn != "" && strings.Contains(sn, idx.SessionPattern) {
			return true, "assumed-role session name " + sn + " matches operator-supplied pattern " + idx.SessionPattern
		}
	}

	// (Signal 3 — a programmatic non-console user-agent — is deferred until
	// corroborate.Record carries UserAgent; it is a weak hint, not a fingerprint.)
	return false, ""
}

// isServiceLinked reports whether an STS assumed-role principal names an
// AWS-reserved service-linked role. Such a role is assumed under its role NAME
// (AWSServiceRoleFor*) — STS flattens the IAM path to the name — so the name
// prefix is the reliable signal, and a customer cannot create it.
func isServiceLinked(principal string) bool {
	return strings.Contains(principal, ":assumed-role/AWSServiceRole")
}
