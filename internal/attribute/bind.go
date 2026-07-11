// Package attribute binds agent sessions to named humans and checks the
// conventions that make such binding possible at all.
//
// The first live divergence report taught the lesson this package encodes:
// principals are shared. SSO credential caches hand the same role and
// session name to every terminal, so "who is this record's principal"
// does not answer "was this the agent". Binding has to happen at the
// credential-session level (access keys) and, where the customer's
// conventions allow, at the human level (STS SourceIdentity, session
// tags). Where conventions don't allow it, saying so precisely — which
// role, which missing trust-policy condition — is the product.
package attribute

import (
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Confidence grades how a claim session and a record session were bound.
type Confidence string

const (
	// ConfidenceCorroborated: corroborated findings prove the agent's
	// claims produced records carrying this credential session's access
	// key — two independent streams fixing the same position.
	ConfidenceCorroborated Confidence = "corroborated"
	// ConfidenceOverlap: the windows merely overlap in time. Weak by
	// design; anything sharing the wall clock qualifies.
	ConfidenceOverlap Confidence = "window-overlap"
)

// Binding is one claim-session ↔ record-session correlation, with the
// strongest human identity the pair supports.
type Binding struct {
	ClaimSessionID  string
	RecordSessionID string
	// Principal is the record session's acting identity ARN.
	Principal  string
	Confidence Confidence
	// Human and Method are the resolved identity: record-side bindings
	// (SourceIdentity, session tags) outrank the claim side's declared
	// operator, because records are written by systems the agent can't edit.
	Human  string
	Method corroborate.AttributionMethod
	// Conflict is set when both sides name a human and they disagree —
	// a finding in its own right, never silently resolved.
	Conflict string
	// Evidence: record IDs proving the binding (corroborated confidence)
	// plus whatever evidence the record session's own attribution carried.
	Evidence []string
}

// ProvenKey names the corroboration that tied an access key to an agent's
// claim session — evidence, not a heuristic.
type ProvenKey struct {
	ClaimSessionID string
	// RecordIDs are the corroborated records carrying this access key.
	RecordIDs []string
}

// ProvenKeys returns the access keys that corroborated findings proved an
// agent wielded: a record carrying one of these keys was made by the same
// credential session the agent's claims corroborated. Bind uses this to bind
// strongly; agent-suspect scoping uses it as its strongest signal — one source
// so the two can never drift.
//
// Scope note: this proves the credential SESSION is the agent's, not that every
// individual record on that key was the agent's action (a shared key can carry
// bystander calls — the UnclaimedRecord posture). It flags the session, not the
// action.
func ProvenKeys(findings []corroborate.Finding) map[string]ProvenKey {
	out := make(map[string]ProvenKey)
	for _, f := range findings {
		if f.Kind != corroborate.Corroborated || f.Record == nil || f.Record.AccessKeyID == "" {
			continue
		}
		pk := out[f.Record.AccessKeyID]
		if pk.ClaimSessionID == "" {
			pk.ClaimSessionID = f.SessionID
		}
		// Only the claim session that first proved the key contributes evidence.
		if pk.ClaimSessionID == f.SessionID {
			pk.RecordIDs = append(pk.RecordIDs, f.Record.ID)
		}
		out[f.Record.AccessKeyID] = pk
	}
	return out
}

// Bind correlates claim-side agent sessions with record-side credential
// sessions. Corroborated findings bind strongly: a finding's record
// carries the access key its claim's session must have wielded. Absent
// that, window overlap binds weakly. Callers scope recordSessions to the
// principals under investigation; overlap alone would happily bind every
// background service session that shares the wall clock.
func Bind(claimSessions, recordSessions []corroborate.Session, findings []corroborate.Finding) []Binding {
	proofByKey := ProvenKeys(findings) // access key → the claim session that proved it

	claimByID := make(map[string]corroborate.Session, len(claimSessions))
	for _, cs := range claimSessions {
		claimByID[cs.ID] = cs
	}

	var out []Binding
	for _, rs := range recordSessions {
		principal, accessKey := splitRecordSessionID(rs.ID)

		if pk, ok := proofByKey[accessKey]; accessKey != "" && ok {
			if cs, ok := claimByID[pk.ClaimSessionID]; ok {
				out = append(out, resolve(cs, rs, Binding{
					Confidence: ConfidenceCorroborated,
					Principal:  principal,
					Evidence:   append(append([]string(nil), pk.RecordIDs...), rs.Attribution.Evidence...),
				}))
				continue
			}
		}

		for _, cs := range claimSessions {
			if overlaps(cs, rs) {
				out = append(out, resolve(cs, rs, Binding{
					Confidence: ConfidenceOverlap,
					Principal:  principal,
					Evidence:   rs.Attribution.Evidence,
				}))
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence == ConfidenceCorroborated
		}
		if out[i].RecordSessionID != out[j].RecordSessionID {
			return out[i].RecordSessionID < out[j].RecordSessionID
		}
		return out[i].ClaimSessionID < out[j].ClaimSessionID
	})
	return out
}

// resolve fills the identity half of a binding: record-side methods
// outrank the declared operator; disagreement is surfaced, not resolved.
func resolve(cs, rs corroborate.Session, b Binding) Binding {
	b.ClaimSessionID = cs.ID
	b.RecordSessionID = rs.ID
	switch {
	case rs.Human != "":
		b.Human, b.Method = rs.Human, rs.Attribution.Method
		if cs.Human != "" && cs.Human != rs.Human {
			b.Conflict = "claim side declared " + cs.Human + " but records bind " + rs.Human
		}
	case cs.Human != "":
		b.Human, b.Method = cs.Human, cs.Attribution.Method
	default:
		b.Method = corroborate.AttrNone
	}
	return b
}

// splitRecordSessionID parses the cloudtrail ingester's session ID format:
// <principal>@<RFC3339>[/<accessKeyID>].
func splitRecordSessionID(id string) (principal, accessKey string) {
	at := strings.IndexByte(id, '@')
	if at < 0 {
		return id, ""
	}
	principal = id[:at]
	if slash := strings.IndexByte(id[at:], '/'); slash >= 0 {
		accessKey = id[at+slash+1:]
	}
	return principal, accessKey
}

func overlaps(a, b corroborate.Session) bool {
	aEnd, bEnd := a.EndedAt, b.EndedAt
	now := time.Now()
	if aEnd.IsZero() {
		aEnd = now
	}
	if bEnd.IsZero() {
		bEnd = now
	}
	return a.StartedAt.Before(bEnd) && b.StartedAt.Before(aEnd)
}
