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
	"strconv"
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

	// ErrorCode is CloudTrail's failure slot: normally an AWS error string
	// (AccessDenied, ThrottlingException, ...). A failed call is an attempt,
	// not a record of the action happening — the ingester refuses errored
	// events the same way k8s refuses code>=400 and gcp refuses
	// status.code!=0. Use Failed(), never emptiness: some services put an
	// HTTP *status* here, and "200" in a field named errorCode means the
	// call succeeded.
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

// principal names the acting identity. Normally that is userIdentity.arn,
// and for AWS's own APIs it always is.
//
// Federated identities carry no ARN. Amazon Managed Grafana records its
// Grafana API calls as {"type":"SAMLUser","userName":"terraform"} — the
// Grafana service account holding the token, with no ARN, no principalId
// and no accessKeyId. Left empty, the Principal makes the record
// unattributable and unsearchable: the report cannot say who acted, and
// --principal cannot select it.
//
// The type prefix is deliberate and is not decoration. A bare "terraform"
// would read as a person or a role and invite exactly the fabricated
// attribution this engine exists to prevent; "SAMLUser/terraform" says
// plainly that this is a federated identity in some other system's namespace
// — a name we are relaying, not an AWS principal we resolved. Nothing binds
// it to a human, and nothing here pretends to.
func principal(arn, typ, userName, principalID string) string {
	if arn != "" {
		return arn
	}
	name := userName
	if name == "" {
		name = principalID
	}
	if name == "" {
		return ""
	}
	if typ == "" {
		return name
	}
	return typ + "/" + name
}

// Failed reports whether this event records an attempt rather than an
// action. Emptiness of ErrorCode is NOT the test.
//
// CloudTrail's errorCode is documented as the AWS error the request
// returned, and for AWS's own APIs it is: AccessDenied, ThrottlingException.
// But services that proxy a foreign HTTP API through CloudTrail put that
// API's *status code* in the field instead. Amazon Managed Grafana does
// exactly this — every Grafana HTTP API call it records carries
// errorCode "200", "500", and so on. Refusing on emptiness therefore
// refuses the successes along with the failures: on the dev-eks corpus it
// discarded 228 successful Grafana mutations (208 dashboard updates, 19
// creates, and the one delete an agent made with a stolen service-account
// token) while keeping nothing but the 8 calls that happened to omit the
// field. The engine read a stream carrying 228 successful writes and
// reported that nothing had happened.
//
// Refusing a real action is the most dangerous mistake this engine can
// make: an unattributed finding over-reports and can be argued down, but a
// silently dropped record is a divergence the report affirmatively denies.
// So the test is whether the code names a failure — and a 2xx status, in
// whatever field a service chose to put it, does not.
func (e *Extracted) Failed() bool {
	if e.ErrorCode == "" {
		return false
	}
	if n, err := strconv.Atoi(e.ErrorCode); err == nil {
		// A numeric code is a foreign API's status, and the rule is the one the
		// other ingesters already use: k8s refuses code >= 400, gcp refuses a
		// non-zero gRPC status. Refuse what NAMES a failure, rather than
		// everything outside 2xx — "0" is gRPC's OK, and a 304 is a successful
		// conditional read. Dropping either would be the very mistake this
		// function exists to undo: a real record discarded at ingestion is a
		// divergence the report then affirmatively denies.
		return n >= 400
	}
	return true // a non-numeric code is an AWS error string: AccessDenied, ...
}

// resourceParamKeys are the requestParameters fields that name a resource across
// the AWS services whose mutations most need production classification. The list
// is curated, not exhaustive — a miss under-escalates (safe: the record still
// surfaces as UnclaimedRecord), never over-consumes — and grows from observed
// logs, the same empirical way the CLI translators do.
var resourceParamKeys = []string{
	"bucketName", "key",
	"functionName",
	"roleName", "userName", "groupName", "policyName", "policyArn",
	"tableName",
	"secretId",
	"keyId",
	"topicArn", "queueUrl", "queueName",
	"streamName",
	"dBInstanceIdentifier", "dBClusterIdentifier",
	"clusterName", "clusterArn",
	"repositoryName",
	"stackName", "stackId",
	"logGroupName",
	"parameterName",
}

// requestParamTargets pulls resource identifiers out of a raw requestParameters
// object. Only top-level string values under known keys are taken; anything else
// (nested shapes, numbers, arrays) is ignored, so an odd event contributes no
// target rather than a wrong one.
func requestParamTargets(raw json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var targets []string
	for _, k := range resourceParamKeys {
		v, ok := m[k]
		if !ok {
			continue
		}
		var str string
		if json.Unmarshal(v, &str) == nil && str != "" {
			targets = append(targets, str)
		}
	}
	return targets
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
		UserName       string `json:"userName"`
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
		Principal:      principal(ev.UserIdentity.ARN, ev.UserIdentity.Type, ev.UserIdentity.UserName, ev.UserIdentity.PrincipalID),
		PrincipalType:  ev.UserIdentity.Type,
		AccessKeyID:    ev.UserIdentity.AccessKeyID,
		SourceIdentity: ev.UserIdentity.SessionContext.SourceIdentity,
	}
	for _, r := range ev.Resources {
		if r.ARN != "" {
			out.Targets = append(out.Targets, r.ARN)
		}
	}
	// CloudTrail does not attach a resources[] array to every management event —
	// notably S3 bucket-level mutations (DeleteBucket, PutBucketPolicy,
	// CreateBucket) carry the bucket only in requestParameters. Left unread, such
	// an event arrives with no target, so --production-match cannot flag it and it
	// under-escalates to UnclaimedRecord instead of Unattributed, dropping a real
	// production action below the report's headline count. When resources[] gave
	// nothing, pull the well-known resource-identifier fields out of
	// requestParameters so the target set — and the production classification that
	// rides on it — is not blind to the operations most worth escalating.
	if len(out.Targets) == 0 && len(ev.RequestParameters) > 0 {
		out.Targets = requestParamTargets(ev.RequestParameters)
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
