package corroborate

import (
	"sort"
	"time"
)

// MatchPolicy bounds how claims and records are correlated. Kept explicit and
// boring on purpose: every parameter here is something an auditor may ask
// about, so defaults are conservative and the policy travels inside the
// evidence package.
type MatchPolicy struct {
	// Window is how far apart a claim and a record may be in time and still
	// correlate. CloudTrail delivery lags up to ~15 minutes; the default
	// accounts for clock skew on top.
	Window time.Duration
	// OperationMap translates claim-vocabulary operations into the record
	// operations they may legitimately produce, e.g.
	// "mcp:create_pull_request" -> {"github-audit:pull_request.create"}.
	// An empty map means only exact string equality matches.
	OperationMap map[string][]string
}

// DefaultMatchPolicy returns the conservative starting policy.
func DefaultMatchPolicy() MatchPolicy {
	return MatchPolicy{Window: 20 * time.Minute}
}

// Join correlates claims against records for a set of sessions and produces
// findings. The algorithm is deliberately simple and total:
//
//  1. Records that fall in no session window and carry no agent fingerprint
//     are out of scope (human activity is not Crossbearing's business).
//  2. Each claim seeks a record: matched pairs become Corroborated (or
//     Mismatch when they correlate but disagree); unmatched claims become
//     UnrecordedClaim.
//  3. Leftover in-window records become UnclaimedRecord.
//  4. Any finding whose record lacks a human binding is escalated to
//     Unattributed when it touches production.
//
// Simplicity is a feature: the join must be explainable to an auditor in one
// paragraph, and every verdict must point at re-fetchable provenance.
func Join(sessions []Session, claims []Claim, records []Record, p MatchPolicy) Report {
	rep := Report{Sessions: sessions}
	if len(claims) == 0 && len(records) == 0 {
		return rep
	}

	bySession := make(map[string][]Claim)
	for _, c := range claims {
		bySession[c.SessionID] = append(bySession[c.SessionID], c)
	}

	humanBySession := make(map[string]string, len(sessions))
	windows := make(map[string][2]time.Time, len(sessions))
	for _, s := range sessions {
		humanBySession[s.ID] = s.Human
		end := s.EndedAt
		if end.IsZero() {
			end = time.Now()
		}
		windows[s.ID] = [2]time.Time{s.StartedAt.Add(-p.Window), end.Add(p.Window)}
	}

	usedRecords := make(map[string]bool)

	// Pass 1: every claim seeks its record.
	for _, s := range sessions {
		sc := bySession[s.ID]
		sort.Slice(sc, func(i, j int) bool { return sc[i].ClaimedAt.Before(sc[j].ClaimedAt) })
		for i := range sc {
			c := sc[i]
			rec, ok := bestRecord(c, records, usedRecords, p)
			switch {
			case !ok:
				rep.Findings = append(rep.Findings, Finding{
					Kind: UnrecordedClaim, SessionID: s.ID, Claim: &sc[i],
					Why: "no infrastructure record corroborates this claim within the match window",
				})
			case operationsAgree(c, rec.Operation, p):
				usedRecords[rec.ID] = true
				rep.Findings = append(rep.Findings, Finding{
					Kind: Corroborated, SessionID: s.ID, Claim: &sc[i], Record: rec,
					Why: "claim corroborated by " + string(rec.Source) + " record " + rec.ID,
				})
			default:
				usedRecords[rec.ID] = true
				rep.Findings = append(rep.Findings, Finding{
					Kind: Mismatch, SessionID: s.ID, Claim: &sc[i], Record: rec,
					Why: "claimed " + c.Operation + " but infrastructure recorded " + rec.Operation,
				})
			}
		}
	}

	// Pass 2: leftover records inside any session window are unclaimed; the
	// unattributed escalation outranks unclaimed when both apply.
	for i := range records {
		r := records[i]
		if usedRecords[r.ID] {
			continue
		}
		sid, inWindow := sessionForRecord(r, windows)
		if !inWindow && r.SourceIdentity == "" {
			continue // out of scope: no session window, no agent fingerprint
		}
		f := Finding{Kind: UnclaimedRecord, SessionID: sid, Record: &records[i],
			Why: "infrastructure recorded this action inside an agent session window; no claim accounts for it"}
		// Escalation defers to the strongest evidence available: a record
		// that itself carries a per-event human identity (STS SourceIdentity,
		// K8s impersonation, GCP/Azure delegation — all normalized into
		// SourceIdentity) is accountable, cloud-proven, and stays unclaimed
		// rather than unattributed. A human inferred only from session
		// declaration or window overlap never de-escalates a record that
		// names no one.
		if r.ProductionTouching && humanBySession[sid] == "" && r.SourceIdentity == "" {
			f.Kind = Unattributed
			f.Why = "production-touching action with agent fingerprints and no named human binding"
		}
		rep.Findings = append(rep.Findings, f)
	}

	return rep
}

// bestRecord finds the closest-in-time unused record plausibly produced by
// the claim, preferring operation agreement, then temporal proximity.
func bestRecord(c Claim, records []Record, used map[string]bool, p MatchPolicy) (*Record, bool) {
	var best *Record
	var bestGap time.Duration
	bestAgrees := false
	for i := range records {
		r := &records[i]
		if used[r.ID] {
			continue
		}
		gap := absDuration(r.RecordedAt.Sub(c.ClaimedAt))
		if gap > p.Window {
			continue
		}
		agrees := operationsAgree(c, r.Operation, p)
		betterClass := agrees && !bestAgrees
		sameClassCloser := agrees == bestAgrees && (best == nil || gap < bestGap)
		if best == nil || betterClass || sameClassCloser {
			best, bestGap, bestAgrees = r, gap, agrees
		}
	}
	return best, best != nil
}

// operationsAgree reports whether a record is a legitimate product of this
// claim. The claim is looked up by ClaimKey, not by its Operation string:
// a shell claim's Operation is a lossy summary that distinct commands
// share, and translating them as one would let any of them corroborate any
// other's record.
func operationsAgree(c Claim, recordOp string, p MatchPolicy) bool {
	if c.Operation == recordOp {
		return true
	}
	for _, mapped := range p.OperationMap[ClaimKey(c)] {
		if mapped == recordOp {
			return true
		}
	}
	return false
}

func sessionForRecord(r Record, windows map[string][2]time.Time) (string, bool) {
	for id, w := range windows {
		if !r.RecordedAt.Before(w[0]) && !r.RecordedAt.After(w[1]) {
			return id, true
		}
	}
	return "", false
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
