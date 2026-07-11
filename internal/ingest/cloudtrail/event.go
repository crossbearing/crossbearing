// Package cloudtrail ingests CloudTrail management events into the
// corroborate vocabulary: each event becomes a record-side
// corroborate.Record with re-fetchable provenance, and assumed-role
// activity is windowed into corroborate.Sessions carrying whatever human
// binding the events themselves prove (STS SourceIdentity, session tags).
//
// Empirical constraints this package is built around:
//   - CloudTrail delivers management events with up to ~15 minutes of lag;
//     callers should not treat a window as settled until that lag has passed.
//   - sts:SourceIdentity, once set, persists across role chaining and cannot
//     be changed for the life of the session — it is the strongest
//     cloud-side binding and appears on every event the session emits
//     (userIdentity.sessionContext.sourceIdentity).
//   - Session tags do NOT reappear on subsequent events; they are visible
//     only in the AssumeRole event's requestParameters, so tag-based
//     binding requires joining a session's events back to the AssumeRole
//     call that created it.
package cloudtrail

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Extracted is everything this package pulls out of one raw CloudTrail
// event JSON document (the CloudTrailEvent field of a LookupEvents result).
type Extracted struct {
	EventID     string
	EventSource string // e.g. "s3.amazonaws.com"
	EventName   string // e.g. "PutObject"
	Region      string
	EventTime   time.Time
	ReadOnly    bool
	UserAgent   string

	// ErrorCode is non-empty when the call failed (AccessDenied,
	// ThrottlingException, ...). A failed call is an attempt, not a record
	// of the action happening — the ingester refuses errored events the
	// same way k8s refuses code>=400 and gcp refuses status.code!=0.
	ErrorCode string

	// Principal is the acting identity ARN (userIdentity.arn). For
	// assumed-role sessions this embeds the role session name:
	// arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION.
	Principal     string
	PrincipalType string // userIdentity.type: AssumedRole, IAMUser, Root, ...

	// SourceIdentity is userIdentity.sessionContext.sourceIdentity — present
	// on every event a session emits when the AssumeRole call set one.
	SourceIdentity string

	// AccessKeyID is userIdentity.accessKeyId — the exact credential
	// session. Two windows with the same principal but different keys are
	// different STS sessions even when their activity interleaves.
	AccessKeyID string

	// Targets are the resource ARNs the event names (resources[].ARN).
	Targets []string

	// AssumeRole-only fields, populated when this event is sts:AssumeRole.
	// AssumedSessionARN is responseElements.assumedRoleUser.arn — the
	// Principal that subsequent events from the granted session will carry,
	// which is how tags and granted identity join back to a session.
	AssumedSessionARN     string
	GrantedSourceIdentity string            // requestParameters/responseElements sourceIdentity
	SessionTags           map[string]string // requestParameters.tags
}

// IsAssumeRole reports whether this event is the sts:AssumeRole call that
// creates a session (the only place session tags are visible).
func (e *Extracted) IsAssumeRole() bool {
	return e.EventSource == "sts.amazonaws.com" && strings.HasPrefix(e.EventName, "AssumeRole")
}

// Operation renders the event in the record vocabulary the matcher joins
// on: the eventSource service prefix plus the eventName, e.g. "s3:PutObject".
// The prefix disambiguates event names that recur across services.
func (e *Extracted) Operation() string {
	svc := strings.TrimSuffix(e.EventSource, ".amazonaws.com")
	if svc == "" {
		return e.EventName
	}
	return svc + ":" + e.EventName
}

// SessionName returns the role session name embedded in an assumed-role
// principal ARN, or "" when the principal is not an assumed-role session.
func (e *Extracted) SessionName() string {
	return sessionNameFromARN(e.Principal)
}

// sessionNameFromARN delegates to corroborate, the single source of
// assumed-role ARN parsing (shared with cmd's convention check and
// agent-suspect scoping).
func sessionNameFromARN(arn string) string {
	return corroborate.SessionNameFromARN(arn)
}

// rawEvent mirrors the slice of the CloudTrail event record schema this
// package reads. Unknown fields are ignored by design: the full raw JSON is
// what provenance digests, not this projection.
type rawEvent struct {
	EventID      string    `json:"eventID"`
	EventTime    time.Time `json:"eventTime"`
	EventSource  string    `json:"eventSource"`
	EventName    string    `json:"eventName"`
	AWSRegion    string    `json:"awsRegion"`
	UserAgent    string    `json:"userAgent"`
	ReadOnly     bool      `json:"readOnly"`
	ErrorCode    string    `json:"errorCode"`
	UserIdentity struct {
		Type           string `json:"type"`
		ARN            string `json:"arn"`
		PrincipalID    string `json:"principalId"`
		AccessKeyID    string `json:"accessKeyId"`
		SessionContext struct {
			SourceIdentity string `json:"sourceIdentity"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	ResponseElements  json.RawMessage `json:"responseElements"`
}

type assumeRoleRequest struct {
	SourceIdentity string `json:"sourceIdentity"`
	Tags           []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

type assumeRoleResponse struct {
	SourceIdentity  string `json:"sourceIdentity"`
	AssumedRoleUser struct {
		ARN string `json:"arn"`
	} `json:"assumedRoleUser"`
}

// ExtractRaw parses one raw CloudTrail event JSON document. It is total
// over well-formed JSON: missing fields yield zero values, never errors —
// only malformed JSON fails, because an event we cannot parse at all cannot
// carry trustworthy provenance.
func ExtractRaw(raw []byte) (Extracted, error) {
	var ev rawEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return Extracted{}, fmt.Errorf("failed to parse cloudtrail event: %w", err)
	}

	out := Extracted{
		EventID:        ev.EventID,
		EventSource:    ev.EventSource,
		EventName:      ev.EventName,
		Region:         ev.AWSRegion,
		EventTime:      ev.EventTime,
		ReadOnly:       ev.ReadOnly,
		UserAgent:      ev.UserAgent,
		ErrorCode:      ev.ErrorCode,
		Principal:      ev.UserIdentity.ARN,
		PrincipalType:  ev.UserIdentity.Type,
		AccessKeyID:    ev.UserIdentity.AccessKeyID,
		SourceIdentity: ev.UserIdentity.SessionContext.SourceIdentity,
	}
	for _, r := range ev.Resources {
		if r.ARN != "" {
			out.Targets = append(out.Targets, r.ARN)
		}
	}

	if out.IsAssumeRole() {
		// requestParameters/responseElements are free-form per event type;
		// parse failures here mean an unexpected shape, not a bad event —
		// the binding fields just stay empty.
		var req assumeRoleRequest
		if len(ev.RequestParameters) > 0 && json.Unmarshal(ev.RequestParameters, &req) == nil {
			out.GrantedSourceIdentity = req.SourceIdentity
			if len(req.Tags) > 0 {
				out.SessionTags = make(map[string]string, len(req.Tags))
				for _, t := range req.Tags {
					out.SessionTags[t.Key] = t.Value
				}
			}
		}
		var resp assumeRoleResponse
		if len(ev.ResponseElements) > 0 && json.Unmarshal(ev.ResponseElements, &resp) == nil {
			out.AssumedSessionARN = resp.AssumedRoleUser.ARN
			if out.GrantedSourceIdentity == "" {
				out.GrantedSourceIdentity = resp.SourceIdentity
			}
		}
	}

	return out, nil
}
