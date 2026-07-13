package corroborate

import (
	"reflect"
	"testing"
	"time"
)

const minute = time.Minute

func TestAWSCLIRecordOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "simple invocation",
			command: "aws sts get-caller-identity --profile stxkxs --output json",
			want:    []string{"sts:GetCallerIdentity"},
		},
		{
			name:    "global flags before service",
			command: "aws --profile x --region us-west-2 cloudtrail lookup-events --max-results 5",
			want:    []string{"cloudtrail:LookupEvents"},
		},
		{
			name:    "env assignment prefix",
			command: "AWS_PROFILE=stxkxs AWS_REGION=us-west-2 aws s3api list-objects-v2 --bucket b",
			want:    []string{"s3:ListObjectsV2"},
		},
		{
			name:    "compound command keeps API call, drops local configure",
			command: "aws sts get-caller-identity --profile stxkxs && aws configure get region",
			want:    []string{"sts:GetCallerIdentity"},
		},
		{
			name:    "piped invocation",
			command: "aws cloudtrail lookup-events --max-results 3 | head -60",
			want:    []string{"cloudtrail:LookupEvents"},
		},
		{
			name:    "two API invocations",
			command: "aws iam list-roles; aws kms list-keys",
			want:    []string{"iam:ListRoles", "kms:ListKeys"},
		},
		{
			name:    "acronym casing",
			command: "aws rds describe-db-instances && aws iam list-mfa-devices",
			want:    []string{"rds:DescribeDBInstances", "iam:ListMFADevices"},
		},
		{
			name:    "sudo wrapper",
			command: "sudo aws ec2 describe-instances",
			want:    []string{"ec2:DescribeInstances"},
		},
		{
			name:    "s3 high-level commands are unmapped",
			command: "aws s3 cp ./a s3://bucket/a && aws s3 ls",
			want:    nil,
		},
		{
			name:    "single-word subcommands are unmapped",
			command: "aws sso login --profile x && aws logs tail my-group",
			want:    nil,
		},
		{
			name:    "aws not in command position",
			command: "echo lean aws client wrappers",
			want:    nil,
		},
		{
			name:    "prose mentioning aws inside quotes",
			command: `git commit -m "extract: graph store and a lean aws client trimmed to five services"`,
			want:    nil,
		},
		{
			name: "heredoc commit message mentioning aws CLI words",
			command: `git commit -m "$(cat <<'EOF'
validate the ingester: aws sts get-caller-identity ran clean
EOF
)"`,
			want: nil,
		},
		{
			name:    "no aws at all",
			command: "go test ./... -count=1 -race",
			want:    nil,
		},
		{
			name:    "aws alone",
			command: "aws",
			want:    nil,
		},
		{
			// Regression: consecutive hyphens used to pass isKebabLower and
			// panic kebabToEventName on the empty split part.
			name:    "consecutive hyphens rejected, not panicked on",
			command: "aws ec2 describe--instances && aws s3api get---object",
			want:    nil,
		},
		{
			name:    "hyphen-edged tokens rejected",
			command: "aws ec2 -describe-instances && aws ec2 describe-instances-",
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AWSCLIRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AWSCLIRecordOps(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestDeriveOperationMap(t *testing.T) {
	t.Parallel()
	claims := []Claim{
		{
			Operation: "Bash(aws sts get-caller-identity --profile stxkxs)",
			Target:    "aws sts get-caller-identity --profile stxkxs",
		},
		{
			Operation: "Bash(aws sts get-caller-identity --profile stxkxs)", // duplicate claim op
			Target:    "aws sts get-caller-identity --profile stxkxs",
		},
		{
			Operation: "Bash(go build ./...)",
			Target:    "go build ./...",
		},
		{
			Operation: "Write",
			Target:    "/repo/main.go",
		},
	}
	m := DeriveOperationMap(claims)

	if len(m) != 1 {
		t.Fatalf("map size = %d, want 1 (only the aws CLI claim derives)", len(m))
	}
	got := m["aws sts get-caller-identity --profile stxkxs"]
	if want := []string{"sts:GetCallerIdentity"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entry = %v, want %v (deduped)", got, want)
	}
}

func TestDeriveOperationMap_FeedsJoin(t *testing.T) {
	t.Parallel()
	// End-to-end through the matcher: a derived map corroborates the claim
	// against its CloudTrail record.
	claims := []Claim{{
		ID: "toolu_1", SessionID: "s1",
		Operation: "Bash(aws sts get-caller-identity)",
		Target:    "aws sts get-caller-identity",
		ClaimedAt: t0,
	}}
	records := []Record{{
		ID: "evt-1", Source: SourceCloudTrail,
		Operation: "sts:GetCallerIdentity", RecordedAt: t0.Add(2 * minute),
	}}
	sessions := []Session{{ID: "s1", StartedAt: t0.Add(-minute), EndedAt: t0.Add(5 * minute)}}

	p := DefaultMatchPolicy()
	p.OperationMap = DeriveOperationMap(claims)
	rep := Join(sessions, claims, records, p)

	if n := rep.Tally()[Corroborated]; n != 1 {
		t.Fatalf("corroborated = %d, want 1; findings: %+v", n, rep.Findings)
	}
}
