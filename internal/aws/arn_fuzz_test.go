package aws

import (
	"strings"
	"testing"
)

func FuzzParseARN(f *testing.F) {
	f.Add("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
	f.Add("arn:aws:s3:::my-bucket")
	f.Add("arn:aws:iam::123456789012:role/my-role")
	f.Add("arn:aws-cn:eks:cn-north-1:123456789012:cluster/test")
	f.Add("arn:aws-us-gov:rds:us-gov-west-1:123456789012:db:my-db")
	f.Add("")
	f.Add("not-an-arn")
	f.Add("arn:")
	f.Add("arn:aws:")
	f.Add("arn:aws:s3")
	f.Add("arn:invalid:s3:::bucket")
	f.Add(strings.Repeat("a", 2048))
	f.Add("arn:aws:s3:us-east-1:123456789012:" + strings.Repeat("x/", 100))

	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := ParseARN(input)
		if err != nil {
			// Error path: must not panic
			return
		}

		// Roundtrip: String() should produce parseable output
		roundtrip := parsed.String()
		reparsed, err := ParseARN(roundtrip)
		if err != nil {
			t.Errorf("roundtrip failed: ParseARN(%q) succeeded but ParseARN(%q) failed: %v",
				input, roundtrip, err)
		}
		if reparsed.String() != roundtrip {
			t.Errorf("double roundtrip mismatch: %q -> %q -> %q",
				input, roundtrip, reparsed.String())
		}

		// Parsed fields should be non-empty for required components
		if parsed.Partition == "" {
			t.Error("parsed ARN has empty Partition")
		}
		if parsed.Service == "" {
			t.Error("parsed ARN has empty Service")
		}
		if parsed.Resource == "" {
			t.Error("parsed ARN has empty Resource")
		}

		// ResourceType and ResourceID must not panic
		_ = parsed.ResourceType()
		_ = parsed.ResourceID()
	})
}

func FuzzValidateARNForService(f *testing.F) {
	f.Add("arn:aws:s3:::my-bucket", "s3")
	f.Add("arn:aws:ec2:us-east-1:123456789012:instance/i-123", "ec2")
	f.Add("arn:aws:ec2:us-east-1:123456789012:instance/i-123", "s3")
	f.Add("", "s3")
	f.Add("not-arn", "ec2")

	f.Fuzz(func(t *testing.T, arn, service string) {
		// Must not panic
		_ = ValidateARNForService(arn, service)
	})
}

func FuzzValidateARNForServiceAndRegion(f *testing.F) {
	f.Add("arn:aws:ec2:us-east-1:123456789012:instance/i-123", "ec2", "us-east-1")
	f.Add("arn:aws:s3:::my-bucket", "s3", "")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, arn, service, region string) {
		// Must not panic
		_ = ValidateARNForServiceAndRegion(arn, service, region)
	})
}

func FuzzIsARN(f *testing.F) {
	f.Add("arn:aws:s3:::bucket")
	f.Add("")
	f.Add("arn:")
	f.Add("ARN:aws:s3:::bucket")
	f.Add(strings.Repeat("arn:", 500))

	f.Fuzz(func(t *testing.T, input string) {
		result := IsARN(input)
		if result != strings.HasPrefix(input, "arn:") {
			t.Errorf("IsARN(%q) = %v, want %v", input, result, strings.HasPrefix(input, "arn:"))
		}
	})
}
