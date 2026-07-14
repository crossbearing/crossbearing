package cloudtrail

import (
	"testing"
	"time"
)

// rawAssumedRoleEvent is a realistic management event emitted by an
// assumed-role session that was created with an STS SourceIdentity.
const rawAssumedRoleEvent = `{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:claude-code-bs",
    "arn": "arn:aws:sts::111122223333:assumed-role/agent-deployer/claude-code-bs",
    "accountId": "111122223333",
    "accessKeyId": "ASIAEXAMPLEKEY01",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::111122223333:role/agent-deployer"
      },
      "attributes": {"creationDate": "2026-06-09T11:55:00Z", "mfaAuthenticated": "false"},
      "sourceIdentity": "bs@example.com"
    }
  },
  "eventTime": "2026-06-09T12:00:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutObject",
  "awsRegion": "us-east-1",
  "userAgent": "aws-sdk-go-v2/1.41.7",
  "readOnly": false,
  "requestParameters": {"bucketName": "prod-artifacts", "key": "release.tar.gz"},
  "resources": [
    {"ARN": "arn:aws:s3:::prod-artifacts/release.tar.gz", "type": "AWS::S3::Object"},
    {"ARN": "arn:aws:s3:::prod-artifacts", "type": "AWS::S3::Bucket"}
  ],
  "eventID": "evt-001",
  "eventType": "AwsApiCall",
  "recipientAccountId": "111122223333"
}`

// rawAssumeRoleEvent is the sts:AssumeRole call that creates a session,
// carrying session tags but no sourceIdentity — the tag-attribution case.
const rawAssumeRoleEvent = `{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::111122223333:user/ci-runner",
    "accountId": "111122223333"
  },
  "eventTime": "2026-06-09T11:50:00Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "readOnly": true,
  "requestParameters": {
    "roleArn": "arn:aws:iam::111122223333:role/agent-deployer",
    "roleSessionName": "ci-agent-7",
    "tags": [
      {"key": "operator", "value": "carol@example.com"},
      {"key": "team", "value": "platform"}
    ]
  },
  "responseElements": {
    "credentials": {"accessKeyId": "ASIAEXAMPLE"},
    "assumedRoleUser": {
      "assumedRoleId": "AROAEXAMPLE:ci-agent-7",
      "arn": "arn:aws:sts::111122223333:assumed-role/agent-deployer/ci-agent-7"
    }
  },
  "eventID": "evt-assume-1",
  "eventType": "AwsApiCall"
}`

func TestExtractRaw_AssumedRoleEvent(t *testing.T) {
	t.Parallel()
	ex, err := ExtractRaw([]byte(rawAssumedRoleEvent))
	if err != nil {
		t.Fatalf("ExtractRaw() error = %v", err)
	}

	if ex.EventID != "evt-001" {
		t.Errorf("EventID = %q, want %q", ex.EventID, "evt-001")
	}
	if got, want := ex.Operation(), "s3:PutObject"; got != want {
		t.Errorf("Operation() = %q, want %q", got, want)
	}
	if ex.Principal != "arn:aws:sts::111122223333:assumed-role/agent-deployer/claude-code-bs" {
		t.Errorf("Principal = %q", ex.Principal)
	}
	if ex.PrincipalType != "AssumedRole" {
		t.Errorf("PrincipalType = %q, want AssumedRole", ex.PrincipalType)
	}
	if ex.SourceIdentity != "bs@example.com" {
		t.Errorf("SourceIdentity = %q, want bs@example.com", ex.SourceIdentity)
	}
	if ex.AccessKeyID != "ASIAEXAMPLEKEY01" {
		t.Errorf("AccessKeyID = %q, want ASIAEXAMPLEKEY01", ex.AccessKeyID)
	}
	if got, want := ex.SessionName(), "claude-code-bs"; got != want {
		t.Errorf("SessionName() = %q, want %q", got, want)
	}
	if len(ex.Targets) != 2 || ex.Targets[0] != "arn:aws:s3:::prod-artifacts/release.tar.gz" {
		t.Errorf("Targets = %v", ex.Targets)
	}
	if want := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC); !ex.EventTime.Equal(want) {
		t.Errorf("EventTime = %v, want %v", ex.EventTime, want)
	}
	if ex.ReadOnly {
		t.Error("ReadOnly = true, want false")
	}
	if ex.IsAssumeRole() {
		t.Error("IsAssumeRole() = true for an s3 event")
	}
}

func TestExtractRaw_AssumeRoleGrant(t *testing.T) {
	t.Parallel()
	ex, err := ExtractRaw([]byte(rawAssumeRoleEvent))
	if err != nil {
		t.Fatalf("ExtractRaw() error = %v", err)
	}

	if !ex.IsAssumeRole() {
		t.Fatal("IsAssumeRole() = false")
	}
	if got, want := ex.Operation(), "sts:AssumeRole"; got != want {
		t.Errorf("Operation() = %q, want %q", got, want)
	}
	if want := "arn:aws:sts::111122223333:assumed-role/agent-deployer/ci-agent-7"; ex.AssumedSessionARN != want {
		t.Errorf("AssumedSessionARN = %q, want %q", ex.AssumedSessionARN, want)
	}
	if ex.GrantedSourceIdentity != "" {
		t.Errorf("GrantedSourceIdentity = %q, want empty", ex.GrantedSourceIdentity)
	}
	if got := ex.SessionTags["operator"]; got != "carol@example.com" {
		t.Errorf("SessionTags[operator] = %q, want carol@example.com", got)
	}
	// The caller is an IAM user, not a session principal.
	if ex.SessionName() != "" {
		t.Errorf("SessionName() = %q, want empty for IAM user caller", ex.SessionName())
	}
}

func TestExtractRaw_AssumeRoleWithSourceIdentity(t *testing.T) {
	t.Parallel()
	raw := `{
      "eventSource": "sts.amazonaws.com",
      "eventName": "AssumeRole",
      "eventID": "evt-assume-2",
      "eventTime": "2026-06-09T09:00:00Z",
      "requestParameters": {"roleArn": "arn:aws:iam::1:role/r", "roleSessionName": "s", "sourceIdentity": "dora@example.com"},
      "responseElements": {"assumedRoleUser": {"arn": "arn:aws:sts::1:assumed-role/r/s"}, "sourceIdentity": "dora@example.com"}
    }`
	ex, err := ExtractRaw([]byte(raw))
	if err != nil {
		t.Fatalf("ExtractRaw() error = %v", err)
	}
	if ex.GrantedSourceIdentity != "dora@example.com" {
		t.Errorf("GrantedSourceIdentity = %q, want dora@example.com", ex.GrantedSourceIdentity)
	}
}

func TestExtractRaw_MalformedJSON(t *testing.T) {
	t.Parallel()
	if _, err := ExtractRaw([]byte(`{"eventID": `)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExtractRaw_MissingFieldsAreZero(t *testing.T) {
	t.Parallel()
	ex, err := ExtractRaw([]byte(`{"eventID": "evt-min", "eventName": "Decrypt"}`))
	if err != nil {
		t.Fatalf("ExtractRaw() error = %v", err)
	}
	if got, want := ex.Operation(), "Decrypt"; got != want {
		t.Errorf("Operation() = %q, want %q (no eventSource prefix)", got, want)
	}
	if ex.SourceIdentity != "" || ex.Principal != "" || len(ex.Targets) != 0 {
		t.Errorf("expected zero identity fields, got %+v", ex)
	}
}

func TestSessionNameFromARN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		arn, want string
	}{
		{"arn:aws:sts::111122223333:assumed-role/agent-deployer/claude-code-bs", "claude-code-bs"},
		{"arn:aws:iam::111122223333:user/alice", ""},
		{"arn:aws:iam::111122223333:role/agent-deployer", ""},
		{"", ""},
		{"arn:aws:sts::111122223333:assumed-role/broken", ""},
	}
	for _, tt := range tests {
		if got := sessionNameFromARN(tt.arn); got != tt.want {
			t.Errorf("sessionNameFromARN(%q) = %q, want %q", tt.arn, got, tt.want)
		}
	}
}

// Amazon Managed Grafana proxies the Grafana HTTP API through CloudTrail
// and puts that API's status code in errorCode — so a successful dashboard
// write is recorded as errorCode "200". Refusing on emptiness discarded 228
// successful mutations on the dev-eks corpus, including a dashboard an agent
// deleted with a service-account token it had lifted from a Kubernetes
// secret. The engine read a stream carrying 228 successful writes and
// reported nothing had happened.
//
// Dropping a real record is the worst error available to this engine: an
// over-report can be argued down, but a silently discarded action is a
// divergence the report affirmatively denies.
func TestFailed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		errorCode string
		want      bool
	}{
		{"no error code: the ordinary AWS success", "", false},
		{"HTTP 200 in errorCode is a SUCCESS (Amazon Managed Grafana)", "200", false},
		{"HTTP 201 created", "201", false},
		{"HTTP 204 no content", "204", false},
		// The rule is the one k8s and gcp already use: refuse what NAMES a
		// failure, not everything outside 2xx. Refusing a real record is the
		// worst mistake available here — the report then affirmatively denies a
		// divergence that happened.
		{"gRPC 0 is OK, not a failure", "0", false},
		{"HTTP 304 is a successful conditional read", "304", false},
		{"HTTP 302 redirect is not a failure", "302", false},
		{"HTTP 400 genuinely failed", "400", true},
		{"HTTP 403 genuinely failed", "403", true},
		{"HTTP 500 genuinely failed", "500", true},
		{"AWS error strings stay errors", "AccessDenied", true},
		{"throttling is an attempt, not an action", "ThrottlingException", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := Extracted{ErrorCode: tt.errorCode}
			if got := e.Failed(); got != tt.want {
				t.Errorf("Failed() with errorCode %q = %v, want %v", tt.errorCode, got, tt.want)
			}
		})
	}
}

// Federated identities carry no ARN. Amazon Managed Grafana records Grafana
// API calls as {"type":"SAMLUser","userName":"terraform"} — the service
// account holding the token. An empty Principal makes the record
// unattributable and unsearchable; a bare "terraform" would read as a person
// and invite the fabricated attribution this engine exists to prevent.
func TestExtract_FederatedPrincipalHasNoARN(t *testing.T) {
	t.Parallel()
	const raw = `{"eventID":"e1","eventTime":"2026-07-13T05:13:23Z","eventSource":"grafana.amazonaws.com",
	  "eventName":"delete","awsRegion":"us-west-2","errorCode":"200","readOnly":false,
	  "userAgent":"curl/8.7.1","sourceIPAddress":"162.197.3.60",
	  "userIdentity":{"type":"SAMLUser","userName":"terraform"}}`

	ex, err := ExtractRaw([]byte(raw))
	if err != nil {
		t.Fatalf("ExtractRaw() error = %v", err)
	}
	if ex.Failed() {
		t.Error("a Grafana call with errorCode 200 was refused as failed — it succeeded")
	}
	if want := "SAMLUser/terraform"; ex.Principal != want {
		t.Errorf("Principal = %q, want %q — type-qualified, so it can never be mistaken for an AWS principal or a human", ex.Principal, want)
	}
	if want := "grafana:delete"; ex.Operation() != want {
		t.Errorf("Operation = %q, want %q", ex.Operation(), want)
	}
	// It binds to nobody: no ARN means no role session, so no human.
	if ex.SessionName() != "" || ex.SourceIdentity != "" {
		t.Errorf("a federated identity must not produce a session binding: session=%q sourceIdentity=%q", ex.SessionName(), ex.SourceIdentity)
	}
}
