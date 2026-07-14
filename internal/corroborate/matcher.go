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

	// AgentRecord reports whether a record is POSITIVELY established as the
	// agent's — not "plausibly", not "in the same window", but linked by
	// evidence: the record names the session's human in its own SourceIdentity,
	// or the operator scoped the run to the agent's principal / role-session,
	// or it shares a credential with a record that did.
	//
	// It exists because agreement on time and operation is CORRELATION, and the
	// join was treating it as proof. A claim and a record can agree on both and
	// have been produced by different actors — an agent writing a deploy script
	// via heredoc while a human deletes the very bucket the script names. With
	// no identity test, that record is consumed as Corroborated, the agent's
	// phantom claim is marked accounted for, and the human's unattributed
	// production deletion DISAPPEARS from the report. That is the worst verdict
	// this engine can reach, and it reaches it silently.
	//
	// Nil means nothing was established. The join then refuses to let any claim
	// consume a record it would otherwise have had to report as Unattributed (the
	// `consumable` guard in Join). It cannot tell who acted, so it does not
	// pretend to — the record falls to Unattributed instead.
	AgentRecord func(Record) bool

	// Now supplies the current time for sessions still believed live. Injected
	// so a report over the same inputs is byte-identical run to run; the
	// evidence package is signed over these findings.
	Now func() time.Time
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
			end = p.now()
		}
		windows[s.ID] = [2]time.Time{s.StartedAt.Add(-p.Window), end.Add(p.Window)}
	}

	// A stable order for window lookup: earliest session first, then by ID.
	order := make([]string, 0, len(sessions))
	for _, s := range sessions {
		order = append(order, s.ID)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := windows[order[i]], windows[order[j]]
		if !a[0].Equal(b[0]) {
			return a[0].Before(b[0])
		}
		return order[i] < order[j]
	})

	usedRecords := make(map[string]bool)

	// Pass 1 — every claim seeks its record, subject to one rule the join used
	// to skip: a claim may not consume a record the engine cannot show is the
	// agent's.
	//
	// A claim CONSUMES the record it matches — that is what corroboration means,
	// and a consumed record leaves the unclaimed accounting for good. So the one
	// record a claim must never take on a time-and-operation coincidence is the
	// record the report would otherwise have had to escalate: a production action
	// bound to no human. Consume it wrongly and the finding does not land in the
	// wrong bucket, it CEASES TO EXIST — a stranger's production deletion reported
	// as the agent's corroborated work, the stranger's divergence erased.
	//
	// An earlier attempt tried to PROVE the agent's credential inside the join,
	// from a non-escalating corroboration. That was unsound: two actors doing
	// `list-buckets` in one window is not proof, it is the exact coincidence the
	// engine exists to catch, and a stranger who did both a read and a delete had
	// the read "prove" their credential and unlock the delete. Credential proof is
	// not the join's job — it is the operator's assertion, and it enters the same
	// way every other judgment does: as INPUT (MatchPolicy.AgentRecord, wired from
	// the operator's --principal scope), never as a guess the engine makes.
	//
	// So a production record is consumable only when the agent's ownership is
	// POSITIVELY established: the record names ITS OWN HUMAN and that human is the
	// one this session is bound to, or the operator scoped this run to the
	// credential. Absent that, the record is left for pass 2, where it becomes
	// Unattributed, and its would-be claim becomes UnrecordedClaim. Both
	// over-report, and over-reporting is the direction this engine is allowed to
	// be wrong in: an unattributed finding can be argued down with evidence; a
	// vanished one cannot be argued with at all.
	//
	// "names its human" is not enough on its own — it must name THE SAME human the
	// agent session is bound to. A production record carrying SourceIdentity=bob,
	// from a human running kubectl under impersonation, names a human; it is still
	// bob's action, not the agent's, and letting the agent's claim consume it
	// reports bob's deletion as the agent's corroborated work and erases bob's
	// finding. So the SourceIdentity must equal the session's human. When the
	// session is unbound (human ""), no SourceIdentity-bearing record matches,
	// which is correct: an unbound agent has proved ownership of nothing.
	//
	// Non-production records are the low-stakes axis and stay freely matchable:
	// requiring identity proof for every read would make the join useless on the
	// unattributed-by-default accounts that are the product's whole premise (real
	// CloudTrail carries no SourceIdentity), and a mis-paired read cannot erase a
	// production divergence.
	matches := make(map[string]*Record, len(claims))
	for _, s := range sessions {
		sc := bySession[s.ID]
		// STABLE. Every claim split out of one shell script carries that tool
		// call's ClaimedAt, so a script's commands are all equal keys here —
		// and their input order IS their execution order. An unstable sort
		// permutes them, and because bestRecord greedily consumes records, a
		// later command's claim can then be credited with an earlier one's
		// record. The counts stay right and the evidence is quietly wrong,
		// which is the failure this engine cannot afford: that claim→record
		// pairing is what the hash chain signs.
		sort.SliceStable(sc, func(i, j int) bool { return sc[i].ClaimedAt.Before(sc[j].ClaimedAt) })
		bySession[s.ID] = sc

		sessionHuman := humanBySession[s.ID]
		consumable := func(r Record) bool {
			if !r.ProductionTouching {
				return true // low-stakes axis: a mis-paired read erases no divergence
			}
			if r.SourceIdentity != "" {
				return r.SourceIdentity == sessionHuman // the agent's own human, not a stranger's
			}
			return p.AgentRecord != nil && p.AgentRecord(r) // unattributed production: operator scope
		}

		// Phase 1 — agreeing matches. AGREEMENT ONLY: a claim must not take an
		// unrelated record just because its own is still out of reach, or it
		// would manufacture a Mismatch another claim would have corroborated.
		for i := range sc {
			if rec, ok := bestRecord(sc[i], records, usedRecords, consumable, true, p); ok {
				usedRecords[rec.ID] = true
				matches[sc[i].ID] = rec
			}
		}

		// Phase 2 — a claim with no agreeing record may still correlate with a
		// disagreeing one: that is a Mismatch, a real finding (claimed a read,
		// performed a write). It runs LAST so no claim manufactures a Mismatch
		// out of a record another claim would have corroborated. Same consumable
		// guard, so a stranger's production record cannot be stolen as a Mismatch
		// either.
		for i := range sc {
			if matches[sc[i].ID] != nil {
				continue
			}
			if rec, ok := bestRecord(sc[i], records, usedRecords, consumable, false, p); ok {
				usedRecords[rec.ID] = true
				matches[sc[i].ID] = rec
			}
		}
	}

	// Emit pass-1 findings in claim order.
	for _, s := range sessions {
		sc := bySession[s.ID]
		for i := range sc {
			c := sc[i]
			rec := matches[c.ID]
			switch {
			case rec == nil:
				rep.Findings = append(rep.Findings, Finding{
					Kind: UnrecordedClaim, SessionID: s.ID, Claim: &sc[i],
					Why: "no infrastructure record corroborates this claim within the match window",
				})
			case operationsAgree(c, rec.Operation, p):
				rep.Findings = append(rep.Findings, Finding{
					Kind: Corroborated, SessionID: s.ID, Claim: &sc[i], Record: rec,
					Why: "claim corroborated by " + string(rec.Source) + " record " + rec.ID,
				})
			default:
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
		sid, inWindow := sessionForRecord(r, order, windows)
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
// bestRecord finds the closest-in-time unused record plausibly produced by the
// claim. mustAgree restricts it to records the claim could legitimately have
// produced — which is how the join separates "this is my record" from "this is
// the nearest record left". Without that separation a claim whose true record is
// merely out of reach will STEAL an unrelated one and report it as a Mismatch,
// inventing a divergence out of two unrelated facts.
func bestRecord(c Claim, records []Record, used map[string]bool, consumable func(Record) bool, mustAgree bool, p MatchPolicy) (*Record, bool) {
	var best *Record
	var bestGap time.Duration
	bestAgrees := false
	for i := range records {
		r := &records[i]
		if used[r.ID] || !consumable(*r) {
			continue
		}
		if mustAgree && !operationsAgree(c, r.Operation, p) {
			continue
		}
		gap := claimGap(c, r.RecordedAt)
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

// sessionForRecord picks the session whose window contains this record.
//
// Sessions overlap routinely (a live CloudTrail run produced 31 in 12 hours),
// and this used to iterate a map — so an overlapped record drew a RUN-DEPENDENT
// SessionID. Because the Unattributed escalation keys on that session's human,
// the finding's KIND could flip between runs on identical inputs, and that
// verdict is what the hash chain signs. Deterministic order is not tidiness
// here; it is the difference between evidence and a coin toss. Ties go to the
// session that started first, then to the lower ID.
func sessionForRecord(r Record, order []string, windows map[string][2]time.Time) (string, bool) {
	for _, id := range order {
		w := windows[id]
		if !r.RecordedAt.Before(w[0]) && !r.RecordedAt.After(w[1]) {
			return id, true
		}
	}
	return "", false
}

// now is the injected clock, defaulting to wall time.
func (p MatchPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// claimGap measures how far a record falls OUTSIDE the span in which the claim
// could have executed. A tool call that ran for four minutes could have produced
// its record at any moment inside those four minutes, so a record landing within
// the span is a zero gap, and only distance beyond either end counts against the
// match window.
//
// Measuring from ClaimedAt alone treats a script as an instant. Agent scripts
// sleep and wait, and every command split out of one inherits the call's start
// time — so on a long script the later commands drift out of the window and the
// join invents an UnrecordedClaim and an UnclaimedRecord for work that plainly
// corroborates. Streams that report no completion time (CompletedAt zero)
// degrade to the point behaviour exactly as before.
func claimGap(c Claim, at time.Time) time.Duration {
	end := c.CompletedAt
	if end.Before(c.ClaimedAt) { // zero, or a stream with clocks out of order
		end = c.ClaimedAt
	}
	switch {
	case at.Before(c.ClaimedAt):
		return c.ClaimedAt.Sub(at)
	case at.After(end):
		return at.Sub(end)
	default:
		return 0 // inside the window the tool call was running
	}
}
