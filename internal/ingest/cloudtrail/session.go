package cloudtrail

import (
	"sort"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// sessions windows assumed-role activity into corroborate.Sessions and
// binds each window to a human where the events themselves prove one.
//
// Grouping key: the assumed-role principal ARN
// (arn:aws:sts::ACCT:assumed-role/ROLE/SESSION) plus the access key ID —
// the exact credential session. The principal alone is routinely shared:
// SSO credential caches hand the same role+session-name to every terminal,
// and role session names get reused. The access key is what separates the
// agent's session from someone else wearing the same principal at the same
// time. Within one key, a silence longer than SessionGap still splits the
// activity, because one credential session can serve distinct working
// sessions (a refreshed SSO cache lives ~8h).
//
// Binding precedence, strongest first:
//  1. sts SourceIdentity carried on the window's own events — set once at
//     AssumeRole, immutable for the session's life, survives role chaining.
//  2. SourceIdentity granted by the AssumeRole event that created the
//     session (joined via responseElements.assumedRoleUser.arn) — same
//     mechanism, seen from the other side.
//  3. A configured session-tag key on that AssumeRole event — tags appear
//     ONLY there, never on subsequent events.
//  4. Nothing: the session stays unattributed, which downstream treats as
//     a finding, not an error.
func (g *Ingester) sessions(events []Extracted) []corroborate.Session {
	type sessionKey struct{ principal, accessKey string }
	byKey := make(map[sessionKey][]Extracted)
	var grants []Extracted // AssumeRole events, joined to windows by AssumedSessionARN
	for _, ex := range events {
		if ex.IsAssumeRole() && ex.AssumedSessionARN != "" {
			grants = append(grants, ex)
		}
		if ex.SessionName() == "" {
			continue // not an assumed-role session principal
		}
		k := sessionKey{ex.Principal, ex.AccessKeyID}
		byKey[k] = append(byKey[k], ex)
	}

	var sessions []corroborate.Session
	for k, evs := range byKey {
		sort.Slice(evs, func(i, j int) bool { return evs[i].EventTime.Before(evs[j].EventTime) })
		start := 0
		for i := 1; i <= len(evs); i++ {
			if i < len(evs) && evs[i].EventTime.Sub(evs[i-1].EventTime) <= g.opts.SessionGap {
				continue
			}
			sessions = append(sessions, g.session(k.principal, k.accessKey, evs[start:i], grants))
			start = i
		}
	}

	sort.Slice(sessions, func(i, j int) bool {
		if !sessions[i].StartedAt.Equal(sessions[j].StartedAt) {
			return sessions[i].StartedAt.Before(sessions[j].StartedAt)
		}
		return sessions[i].ID < sessions[j].ID
	})
	return sessions
}

// session builds one Session from a window of same-credential events.
func (g *Ingester) session(principal, accessKey string, window []Extracted, grants []Extracted) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	id := principal + "@" + first.EventTime.UTC().Format(time.RFC3339)
	if accessKey != "" {
		// The key suffix keeps concurrent same-principal sessions distinct.
		id += "/" + accessKey
	}
	s := corroborate.Session{
		// Deterministic and self-describing: the principal names role and
		// session name, the timestamp separates re-assumptions, the access
		// key separates credential sessions sharing both.
		ID:        id,
		Agent:     first.SessionName(),
		StartedAt: first.EventTime,
		EndedAt:   last.EventTime,
		Attribution: corroborate.Attribution{
			Method: corroborate.AttrNone,
		},
	}

	// 1. SourceIdentity on the window's own events.
	var evidence []string
	human := ""
	for _, ex := range window {
		if ex.SourceIdentity == "" {
			continue
		}
		if human == "" {
			human = ex.SourceIdentity
		}
		if ex.SourceIdentity == human {
			evidence = append(evidence, ex.EventID)
		}
	}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{
			Method:   corroborate.AttrSTSSourceIdentity,
			Evidence: evidence,
		}
		return s
	}

	// 2 & 3. The AssumeRole grant that created this session: the latest
	// grant for this principal at or before the window's end (delivery
	// ordering can place it anywhere inside the window).
	grant, ok := latestGrant(grants, principal, last.EventTime)
	if !ok {
		return s
	}
	if grant.GrantedSourceIdentity != "" {
		s.Human = grant.GrantedSourceIdentity
		s.Attribution = corroborate.Attribution{
			Method:   corroborate.AttrSTSSourceIdentity,
			Evidence: []string{grant.EventID},
		}
		return s
	}
	for _, key := range g.opts.SessionTagKeys {
		if v := grant.SessionTags[key]; v != "" {
			s.Human = v
			s.Attribution = corroborate.Attribution{
				Method:   corroborate.AttrSessionTags,
				Evidence: []string{grant.EventID},
			}
			return s
		}
	}
	return s
}

func latestGrant(grants []Extracted, principal string, notAfter time.Time) (Extracted, bool) {
	var best Extracted
	found := false
	for _, gr := range grants {
		if gr.AssumedSessionARN != principal || gr.EventTime.After(notAfter) {
			continue
		}
		if !found || gr.EventTime.After(best.EventTime) {
			best, found = gr, true
		}
	}
	return best, found
}
