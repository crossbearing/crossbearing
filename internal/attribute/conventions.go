package attribute

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// RoleConventions is the read-only answer to "can sessions on this role be
// attributed to a human at all?" — parsed from the role's trust policy.
// It feeds the report (explaining WHY a session is unattributable) and the
// evidence package (proving the convention gap to an auditor).
type RoleConventions struct {
	RoleARN string

	// RequiresSourceIdentity: the trust policy conditions assumption on
	// sts:SourceIdentity being present (StringEquals/StringLike, or
	// Null:false), so every session on this role must name an identity.
	RequiresSourceIdentity bool
	// ForbidsSourceIdentity: a Null:true condition — assumption is only
	// allowed WITHOUT a SourceIdentity. The convention is actively off.
	ForbidsSourceIdentity bool
	// AllowsTagSession: sts:TagSession is granted, so sessions CAN carry
	// binding tags (whether anything enforces them is a separate question).
	AllowsTagSession bool
	// RequiredTagKeys are the session-tag keys the trust policy REQUIRES
	// on assumption (aws:RequestTag/<key> conditions in requiring form) —
	// the difference between a tag convention that binds and one that's
	// merely available.
	RequiredTagKeys []string

	// Evidence digests the trust policy exactly as checked.
	Evidence corroborate.Provenance
}

// Gaps renders the convention shortfalls as operator-readable sentences,
// empty when the role supports attribution.
func (rc RoleConventions) Gaps() []string {
	var gaps []string
	switch {
	case rc.ForbidsSourceIdentity:
		gaps = append(gaps, "trust policy FORBIDS sts:SourceIdentity (Null:true) — sessions on this role can never carry a human binding")
	case !rc.RequiresSourceIdentity && len(rc.RequiredTagKeys) > 0:
		// Tags enforced is a real convention — note the stronger option
		// rather than calling the role anonymous.
		gaps = append(gaps, "binds via required session tags ("+strings.Join(rc.RequiredTagKeys, ", ")+"); requiring sts:SourceIdentity would be stronger — it survives role chaining and cannot be unset mid-session")
	case !rc.RequiresSourceIdentity:
		gaps = append(gaps, "trust policy does not require sts:SourceIdentity — sessions on this role are anonymous-by-default and agent activity is indistinguishable from anyone else's")
		if rc.AllowsTagSession {
			gaps = append(gaps, "sts:TagSession is allowed but no aws:RequestTag condition requires a tag — the tag convention exists but is optional, and optional conventions don't bind agents")
		}
	}
	if !rc.AllowsTagSession {
		gaps = append(gaps, "sts:TagSession is not allowed — session tags cannot carry a binding either")
	}
	return gaps
}

// CheckTrustPolicy parses one role trust policy (plain JSON, as
// aws.IAMService.GetRole returns it) and reports the attribution
// conventions it supports. Pure function: callers fetch, this judges.
func CheckTrustPolicy(roleARN, policyJSON string) (RoleConventions, error) {
	rc := RoleConventions{
		RoleARN: roleARN,
		Evidence: corroborate.Provenance{
			Locator: "iam:" + roleARN + "#trust-policy",
			Digest:  corroborate.DigestHex([]byte(policyJSON)),
		},
	}

	var doc struct {
		Statement jsonList[statement] `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return rc, fmt.Errorf("failed to parse trust policy for %s: %w", roleARN, err)
	}

	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if st.allowsAction("sts:TagSession") {
			rc.AllowsTagSession = true
		}
		if !st.allowsAssume() {
			continue
		}
		for op, keys := range st.Condition {
			for key, vals := range keys {
				switch {
				case strings.EqualFold(key, "sts:SourceIdentity"):
					switch {
					case strings.EqualFold(op, "Null"):
						// Null:true → key must be ABSENT; Null:false → present.
						if len(vals) > 0 && strings.EqualFold(vals[0], "true") {
							rc.ForbidsSourceIdentity = true
						} else {
							rc.RequiresSourceIdentity = true
						}
					case strings.Contains(strings.ToLower(op), "stringnotequals"):
						// Excludes specific values; does not force presence.
					default:
						// StringEquals / StringLike / ForAnyValue variants: the
						// key must be present and match — the requirement form.
						rc.RequiresSourceIdentity = true
					}
				case len(key) > len("aws:RequestTag/") && strings.EqualFold(key[:len("aws:RequestTag/")], "aws:RequestTag/"):
					// A required tag: the assumption only succeeds when the
					// session carries this tag (requiring forms only; a
					// Null:true or StringNotEquals on a tag is not enforcement).
					requiring := !strings.Contains(strings.ToLower(op), "stringnotequals") &&
						!(strings.EqualFold(op, "Null") && len(vals) > 0 && strings.EqualFold(vals[0], "true"))
					if requiring {
						tag := key[len("aws:RequestTag/"):]
						if !slices.Contains(rc.RequiredTagKeys, tag) {
							rc.RequiredTagKeys = append(rc.RequiredTagKeys, tag)
						}
					}
				}
			}
		}
	}
	slices.Sort(rc.RequiredTagKeys)
	return rc, nil
}

// statement is the slice of an IAM policy statement this checker reads,
// tolerant of IAM's string-or-array JSON shapes.
type statement struct {
	Effect    string                          `json:"Effect"`
	Action    jsonList[string]                `json:"Action"`
	Condition map[string]map[string]jsonElems `json:"Condition"`
}

func (st *statement) allowsAssume() bool {
	for _, a := range st.Action {
		if strings.HasPrefix(strings.ToLower(a), "sts:assumerole") || a == "sts:*" || a == "*" {
			return true
		}
	}
	return false
}

func (st *statement) allowsAction(action string) bool {
	for _, a := range st.Action {
		if strings.EqualFold(a, action) || a == "sts:*" || a == "*" {
			return true
		}
	}
	return false
}

// jsonList decodes IAM's "T or [T]" convention.
type jsonList[T any] []T

func (l *jsonList[T]) UnmarshalJSON(data []byte) error {
	var many []T
	if err := json.Unmarshal(data, &many); err == nil {
		*l = many
		return nil
	}
	var one T
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = []T{one}
	return nil
}

// jsonElems is jsonList for condition values, which are strings, bools, or
// arrays of either depending on who wrote the policy.
type jsonElems []string

func (e *jsonElems) UnmarshalJSON(data []byte) error {
	var raw jsonList[any]
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, v := range raw {
		*e = append(*e, fmt.Sprintf("%v", v))
	}
	return nil
}
