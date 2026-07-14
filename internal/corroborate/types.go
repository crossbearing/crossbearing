// Package corroborate is Crossbearing's core: the join between what agents
// CLAIM they did and what infrastructure RECORDED. Claim-side streams (agent
// telemetry, receipts, CI logs) are inherently self-reported; record-side
// streams (CloudTrail, GitHub audit, Kubernetes audit) are the ground truth
// the platform keeps anyway. A divergence between the two — in either
// direction — is the finding everything else in the product packages.
package corroborate

import "time"

// StreamKind separates self-reported streams from infrastructure records.
// The asymmetry is the whole point: claims describe intent from inside the
// agent's process; records are written by systems the agent cannot edit.
type StreamKind string

const (
	StreamClaim  StreamKind = "claim"
	StreamRecord StreamKind = "record"
)

// Source identifies a concrete stream a Claim or Record came from.
type Source string

const (
	SourceClaudeCodeTelemetry  Source = "claude-code-otel"
	SourceClaudeCodeTranscript Source = "claude-code-transcript"
	SourceBedrockInvocation    Source = "bedrock-invocation" // Bedrock model-invocation logging (claim side: tool_use/tool_result)
	SourceAgentReceipt         Source = "agent-receipt"      // ACTA / Microsoft toolkit style receipts
	SourceCIRunnerLog          Source = "ci-runner"
	SourceCloudTrail           Source = "aws-cloudtrail"
	SourceGitHubAudit          Source = "github-audit"
	SourceK8sAudit             Source = "k8s-audit"
	SourceGCPAudit             Source = "gcp-audit"
	SourceAzureActivity        Source = "azure-activity"
)

// Session is one agent working session: the unit attribution binds to a
// human and the window the join correlates over.
type Session struct {
	ID string
	// Agent names the acting tool ("claude-code", "cursor", "ci:github-actions").
	Agent string
	// Human is the named identity this session is bound to; empty until
	// attribution succeeds. Unattributed sessions that touch production are
	// first-class findings, not errors.
	Human string
	// Attribution records how Human was established (or why it wasn't).
	Attribution Attribution
	StartedAt   time.Time
	// EndedAt is zero while the session is believed live.
	EndedAt time.Time
}

// AttributionMethod is the convention that bound a session to a human.
type AttributionMethod string

const (
	// AttrSTSSourceIdentity: the session's cloud calls carried an STS
	// SourceIdentity naming the human — the strongest cloud-side binding.
	AttrSTSSourceIdentity AttributionMethod = "sts-source-identity"
	// AttrSessionTags: sts:TagSession tags carried the binding.
	AttrSessionTags AttributionMethod = "sts-session-tags"
	// AttrGitHubApp: a GitHub App installation / actor mapping named the human.
	AttrGitHubApp AttributionMethod = "github-app"
	// AttrK8sImpersonation: Kubernetes impersonation headers named the human.
	AttrK8sImpersonation AttributionMethod = "k8s-impersonation"
	// AttrGCPDelegation: a GCP serviceAccountDelegationInfo chain named the
	// human a service account acted on behalf of — the same convention slot
	// as STS SourceIdentity and K8s impersonation, GCP-side.
	AttrGCPDelegation AttributionMethod = "gcp-delegation"
	// AttrAzureDelegation: an Azure workload identity (service principal /
	// managed identity) acted with a user-delegated token, and the token's
	// claims named the human (upn). The same convention slot again, Azure-side.
	AttrAzureDelegation AttributionMethod = "azure-delegation"
	// AttrActorIdentity: the record stream's authenticated actor IS the
	// named human (a GitHub username, a K8s OIDC user) — strong because the
	// platform authenticated them, but it cannot separate the human's own
	// actions from an agent wearing their token; conventions above do.
	AttrActorIdentity AttributionMethod = "actor-identity"
	// AttrDeclared: the claim stream itself declared an operator identity —
	// self-reported, therefore the weakest method; corroboration may upgrade it.
	AttrDeclared AttributionMethod = "declared"
	// AttrNone: no convention produced a binding.
	AttrNone AttributionMethod = "unattributed"
)

// Attribution is the outcome of binding a session to a human identity.
type Attribution struct {
	Method AttributionMethod
	// Evidence points at the raw material that established the binding
	// (e.g. the CloudTrail event ID carrying the SourceIdentity).
	Evidence []string
}

// Claim is one action an agent-side stream says happened.
type Claim struct {
	ID        string
	SessionID string
	Source    Source
	// Operation in the claim's own vocabulary ("Write", "Bash(git push)",
	// "mcp:create_pull_request"). Mapping into record vocabulary is the
	// matcher's job, not the ingester's.
	Operation string
	// Target is the claimed object of the action (file path, repo, ARN, URL).
	Target string
	// ClaimedAt is when the claim's tool call STARTED.
	ClaimedAt time.Time
	// CompletedAt is when it returned — the moment the agent's own stream
	// proved it executed. Zero when the stream doesn't say.
	//
	// A shell claim is not an instant. Agent scripts sleep, poll, and wait on
	// rollouts (the dev-eks corpus has `sleep 90` and `rollout status
	// --timeout=150s` inside single tool calls), and every command split out of
	// one script inherits that call's ClaimedAt. Matched as a point, a long
	// script's later commands fall outside the window and become UnrecordedClaim
	// while their records become UnclaimedRecord — both false, and the exact
	// pair the engine exists to avoid inventing. The action happened somewhere
	// in [ClaimedAt, CompletedAt]; the matcher correlates against that span.
	CompletedAt time.Time
	// Raw preserves provenance: where exactly this claim can be re-read.
	Raw Provenance
}

// Record is one action an infrastructure audit stream recorded.
type Record struct {
	ID     string
	Source Source
	// Operation in the record's vocabulary (CloudTrail eventName,
	// GitHub audit action, K8s audit verb+resource).
	Operation string
	// Principal is the recorded acting identity (ARN, GitHub actor, K8s user).
	Principal string
	// SourceIdentity carries the STS SourceIdentity / session-tag values if
	// present — the hook attribution conventions hang on.
	SourceIdentity string
	// AccessKeyID identifies the exact credential session that made the
	// call. Principals are routinely shared (SSO credential caches, reused
	// role session names) — the access key is what separates "the agent's
	// session" from "someone else wearing the same role at the same time".
	AccessKeyID string
	// Targets are the recorded objects (ARNs, repo names, object keys).
	Targets    []string
	RecordedAt time.Time
	// ProductionTouching marks records whose target set falls inside the
	// configured production scope; these escalate finding severity.
	ProductionTouching bool
	Raw                Provenance
}

// Provenance says where a Claim or Record can be independently re-fetched —
// the property that makes a finding auditable rather than asserted.
type Provenance struct {
	// Locator is stream-specific: an S3 object key + event ID for CloudTrail,
	// a GitHub audit-log cursor, a telemetry span ID.
	Locator string
	// Digest is the SHA-256 of the raw entry as ingested, so the evidence
	// package can prove the input didn't change after the join ran.
	Digest string
}

// FindingKind classifies the result of joining claims against records.
type FindingKind string

const (
	// Corroborated: a claim and a record agree (within the match policy).
	Corroborated FindingKind = "corroborated"
	// UnclaimedRecord: infrastructure recorded an action inside an agent
	// session's window that no claim accounts for — the agent (or something
	// wearing its credentials) did more than it said.
	UnclaimedRecord FindingKind = "unclaimed-record"
	// UnrecordedClaim: an agent claimed an action no record corroborates —
	// either the claim is wrong or a record stream is missing/misconfigured.
	UnrecordedClaim FindingKind = "unrecorded-claim"
	// Unattributed: a record carries agent fingerprints but no convention
	// binds it to a named human — the headline governance gap.
	Unattributed FindingKind = "unattributed"
	// Mismatch: claim and record correlate but disagree on operation or
	// target (e.g. claimed read-only, recorded a write).
	Mismatch FindingKind = "mismatch"
)

// Finding is one joined result. Findings — not raw logs — are what the
// evidence package signs and what the divergence report renders.
type Finding struct {
	Kind      FindingKind
	SessionID string
	// Claim and Record are the joined halves; either may be zero-valued
	// depending on Kind (an UnclaimedRecord has no Claim, etc.).
	Claim  *Claim
	Record *Record
	// Why explains the match or the divergence in one operator-readable
	// sentence; the report and the auditor artifact both surface it verbatim.
	Why string
}

// Report is the divergence report over a window: the week-one artifact.
type Report struct {
	From, To time.Time
	Sessions []Session
	Findings []Finding
}

// Tally summarises a report the way the demo opens: counts first.
func (r *Report) Tally() map[FindingKind]int {
	t := make(map[FindingKind]int, 5)
	for _, f := range r.Findings {
		t[f.Kind]++
	}
	return t
}
