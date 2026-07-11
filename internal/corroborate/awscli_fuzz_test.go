package corroborate

import (
	"strings"
	"testing"
)

// FuzzAWSCLIRecordOps holds the translator panic-free and shape-correct
// over arbitrary input. Claim targets are agent-written shell text — an
// untrusted stream — and a malformed command must scope a claim out of
// corroboration, never crash the report run.
func FuzzAWSCLIRecordOps(f *testing.F) {
	f.Add("aws sts get-caller-identity --profile x")
	f.Add("aws ec2 describe--instances")
	f.Add(`git commit -m "the aws client" && aws s3 ls`)
	f.Add("AWS_PROFILE=x aws --region us-west-2 cloudtrail lookup-events | jq .")
	f.Add("aws '" + strings.Repeat("-", 64))
	f.Add("aws \\")
	f.Add("aws s3api \"unterminated")
	f.Add("echo `aws iam list-roles`; aws kms list-keys")

	f.Fuzz(func(t *testing.T, command string) {
		ops := AWSCLIRecordOps(command) // must not panic
		for _, op := range ops {
			svc, name, ok := strings.Cut(op, ":")
			if !ok || svc == "" || name == "" {
				t.Fatalf("malformed record op %q from %q", op, command)
			}
		}
	})
}
