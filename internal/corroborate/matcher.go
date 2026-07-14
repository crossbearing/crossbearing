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
	// consume a record it would otherwise have had to report as Unattributed —
	// see canConsume. It cannot tell who acted, so it does not pretend to.
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

	// Pass 1, in two phases, because "who produced this record" is the question
	// the join used to skip.
	//
	// A claim CONSUMES the record it matches — that is what corroboration means,
	// and a consumed record leaves the unclaimed accounting for good. So the one
	// record a claim must never take on the strength of a time-and-operation
	// coincidence is the record the report would otherwise have had to escalate:
	// a production-touching action bound to no human. Take that wrongly and the
	// finding does not land in the wrong bucket, it CEASES TO EXIST.
	//
	// But an agent's own production actions are exactly that shape, and they must
	// still corroborate — so the credential has to be established from evidence,
	// without circularity:
	//
	//	phase A — match only records whose loss cannot hide anything (not
	//	          production-touching, or already naming their own human, or in a
	//	          session with a bound operator). Every corroboration here PROVES
	//	          a credential belongs to the agent, because the agent's own claim
	//	          named the action it performed.
	//	phase B — the remaining claims may now reach the protected records, but
	//	          only those carrying a credential phase A proved — or one the
	//	          operator positively scoped (MatchPolicy.AgentRecord).
	//
	// A record from a credential neither phase established is never consumed. It
	// falls to pass 2 as Unattributed, and its would-be claim becomes an
	// UnrecordedClaim. Both are over-reports, and over-reporting is the direction
	// this engine is allowed to be wrong in: an unattributed finding can be argued
	// down with evidence; a vanished one cannot be argued with at all.
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

		human := humanBySession[s.ID]
		proven := make(map[string]bool) // credentials proved to be this agent's

		// Phase A — corroborations against records whose loss can hide nothing.
		// AGREEMENT ONLY: a claim must not take an unrelated record here just
		// because its own is still out of reach. Each match proves a credential
		// is the agent's, because the agent named the very action the record
		// shows.
		unprotected := func(r Record) bool { return !wouldEscalate(r, human) }
		for i := range sc {
			rec, ok := bestRecord(sc[i], records, usedRecords, unprotected, true, p)
			if !ok {
				continue
			}
			usedRecords[rec.ID] = true
			matches[sc[i].ID] = rec
			proven[credentialKey(*rec)] = true
		}

		// mine: everything phase A could reach, plus the protected records now
		// carrying a credential the agent has been proved to hold — or one the
		// operator positively scoped.
		mine := func(r Record) bool {
			if !wouldEscalate(r, human) {
				return true
			}
			if proven[credentialKey(r)] {
				return true
			}
			return p.AgentRecord != nil && p.AgentRecord(r)
		}

		// Phase B — corroborations against the agent's OWN production actions,
		// which are exactly the shape phase A had to protect. Still agreement
		// only.
		for i := range sc {
			if matches[sc[i].ID] != nil {
				continue
			}
			if rec, ok := bestRecord(sc[i], records, usedRecords, mine, true, p); ok {
				usedRecords[rec.ID] = true
				matches[sc[i].ID] = rec
			}
		}

		// Phase C — a claim with no agreeing record anywhere may still correlate
		// with a disagreeing one: that is a Mismatch, and it is a real finding
		// (claimed a read, performed a write). It runs LAST so that no claim can
		// manufacture a Mismatch out of a record another claim would have
		// corroborated.
		for i := range sc {
			if matches[sc[i].ID] != nil {
				continue
			}
			if rec, ok := bestRecord(sc[i], records, usedRecords, mine, false, p); ok {
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

// wouldEscalate reports whether pass 2 would have to call this record
// Unattributed: a production-touching action that neither the record itself nor
// its session binds to a named human. These are the findings whose silent
// disappearance is catastrophic, and therefore the records a claim may not
// consume on a coincidence.
//
// It is deliberately the SAME predicate the Unattributed escalation uses below,
// so the set a claim may not quietly take is exactly the set the report would
// otherwise have had to raise.
func wouldEscalate(r Record, sessionHuman string) bool {
	return r.ProductionTouching && sessionHuman == "" && r.SourceIdentity == ""
}

// credentialKey identifies the credential session behind a record. The access
// key separates concurrent sessions sharing one principal (SSO caches hand the
// same role to every terminal); principals that carry no key fall back to the
// principal itself.
func credentialKey(r Record) string {
	if r.AccessKeyID != "" {
		return string(r.Source) + "/" + r.AccessKeyID
	}
	return string(r.Source) + "/" + r.Principal
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

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
