package aws

import (
	"testing"
)

func TestParseARN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		arn     string
		want    ARN
		wantErr bool
	}{
		{
			name: "EC2 instance",
			arn:  "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
			want: ARN{Partition: "aws", Service: "ec2", Region: "us-east-1", AccountID: "123456789012", Resource: "instance/i-1234567890abcdef0"},
		},
		{
			name: "S3 bucket",
			arn:  "arn:aws:s3:::my-bucket",
			want: ARN{Partition: "aws", Service: "s3", Region: "", AccountID: "", Resource: "my-bucket"},
		},
		{
			name: "IAM role",
			arn:  "arn:aws:iam::123456789012:role/MyRole",
			want: ARN{Partition: "aws", Service: "iam", Region: "", AccountID: "123456789012", Resource: "role/MyRole"},
		},
		{
			name: "EKS cluster",
			arn:  "arn:aws:eks:us-west-2:123456789012:cluster/my-cluster",
			want: ARN{Partition: "aws", Service: "eks", Region: "us-west-2", AccountID: "123456789012", Resource: "cluster/my-cluster"},
		},
		{
			name: "RDS colon separator",
			arn:  "arn:aws:rds:us-east-1:123456789012:db:my-database",
			want: ARN{Partition: "aws", Service: "rds", Region: "us-east-1", AccountID: "123456789012", Resource: "db:my-database"},
		},
		{
			name: "GovCloud partition",
			arn:  "arn:aws-us-gov:s3:::my-gov-bucket",
			want: ARN{Partition: "aws-us-gov", Service: "s3", Region: "", AccountID: "", Resource: "my-gov-bucket"},
		},
		{name: "empty string", arn: "", wantErr: true},
		{name: "not an ARN", arn: "not-an-arn", wantErr: true},
		{name: "too few components", arn: "arn:aws:ec2", wantErr: true},
		{name: "empty service", arn: "arn:aws::us-east-1:123456789012:resource", wantErr: true},
		{name: "empty resource", arn: "arn:aws:ec2:us-east-1:123456789012:", wantErr: true},
		{name: "invalid partition", arn: "arn:invalid:ec2:us-east-1:123456789012:instance/i-123", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseARN(tt.arn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseARN() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("ParseARN() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestARN_String(t *testing.T) {
	t.Parallel()
	arn := ARN{Partition: "aws", Service: "ec2", Region: "us-east-1", AccountID: "123456789012", Resource: "instance/i-123"}
	want := "arn:aws:ec2:us-east-1:123456789012:instance/i-123"
	if got := arn.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestARN_ResourceType(t *testing.T) {
	t.Parallel()
	tests := []struct{ resource, want string }{
		{"instance/i-123", "instance"},
		{"db:my-database", "db"},
		{"my-bucket", ""},
	}
	for _, tt := range tests {
		if got := (ARN{Resource: tt.resource}).ResourceType(); got != tt.want {
			t.Errorf("ResourceType(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}

func TestARN_ResourceID(t *testing.T) {
	t.Parallel()
	tests := []struct{ resource, want string }{
		{"instance/i-123", "i-123"},
		{"db:my-database", "my-database"},
		{"my-bucket", "my-bucket"},
	}
	for _, tt := range tests {
		if got := (ARN{Resource: tt.resource}).ResourceID(); got != tt.want {
			t.Errorf("ResourceID(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}

func TestValidateARN(t *testing.T) {
	t.Parallel()
	if err := ValidateARN("arn:aws:ec2:us-east-1:123456789012:instance/i-123"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateARN("not-an-arn"); err == nil {
		t.Error("expected error for invalid ARN")
	}
}

func TestValidateARNForService(t *testing.T) {
	t.Parallel()
	if err := ValidateARNForService("arn:aws:eks:us-west-2:123:cluster/c1", "eks"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateARNForService("arn:aws:ec2:us-west-2:123:instance/i-1", "eks"); err == nil {
		t.Error("expected service mismatch error")
	}
}

func TestValidateARNForServiceAndRegion(t *testing.T) {
	t.Parallel()
	if err := ValidateARNForServiceAndRegion("arn:aws:eks:us-west-2:123:cluster/c1", "eks", "us-west-2"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateARNForServiceAndRegion("arn:aws:eks:us-east-1:123:cluster/c1", "eks", "us-west-2"); err == nil {
		t.Error("expected region mismatch error")
	}
	if err := ValidateARNForServiceAndRegion("arn:aws:eks:us-east-1:123:cluster/c1", "eks", ""); err != nil {
		t.Errorf("unexpected error with empty region: %v", err)
	}
}

func TestIsARN(t *testing.T) {
	t.Parallel()
	if !IsARN("arn:aws:s3:::bucket") {
		t.Error("expected true for valid ARN prefix")
	}
	if IsARN("not-an-arn") {
		t.Error("expected false for non-ARN string")
	}
}

func TestParseARN_Roundtrip(t *testing.T) {
	t.Parallel()
	arns := []string{
		"arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
		"arn:aws:s3:::my-bucket",
		"arn:aws:iam::123456789012:role/MyRole",
		"arn:aws-cn:ec2:cn-north-1:123456789012:vpc/vpc-12345",
	}
	for _, original := range arns {
		parsed, err := ParseARN(original)
		if err != nil {
			t.Fatalf("ParseARN(%q) unexpected error: %v", original, err)
		}
		if got := parsed.String(); got != original {
			t.Errorf("roundtrip failed: got %q, want %q", got, original)
		}
	}
}

func BenchmarkParseARN(b *testing.B) {
	arn := "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
	for b.Loop() {
		_, _ = ParseARN(arn)
	}
}
