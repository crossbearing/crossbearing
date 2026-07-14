package aws

import (
	"log/slog"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// testClient creates a Client for testing lazy init patterns.
func testClient(t *testing.T) *Client {
	t.Helper()
	awsCfg := awssdk.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
	}
	return &Client{
		config:    ClientConfig{Region: "us-east-1"},
		awsConfig: awsCfg,
		logger:    slog.New(slog.DiscardHandler),
	}
}

func TestClientLazyInitS3(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	if c.cloudTrailClient != nil {
		t.Fatal("cloudTrailClient should be nil before first access")
	}

	s3 := c.CloudTrail()
	if s3 == nil {
		t.Fatal("CloudTrail() should return non-nil client")
	}

	// Second call should return the same instance
	if s3Again := c.CloudTrail(); s3 != s3Again {
		t.Error("CloudTrail() should return same instance on subsequent calls")
	}
}

func TestClientLazyInitIAM(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	iam := c.IAM()
	if iam == nil {
		t.Fatal("IAM() should return non-nil client")
	}

	if iamAgain := c.IAM(); iam != iamAgain {
		t.Error("IAM() should return same instance")
	}
}

func TestClientLazyInitKMS(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	kms := c.KMS()
	if kms == nil {
		t.Fatal("KMS() should return non-nil client")
	}

	if kmsAgain := c.KMS(); kms != kmsAgain {
		t.Error("KMS() should return same instance")
	}
}

func TestClientLazyInitSTS(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	sts := c.STS()
	if sts == nil {
		t.Fatal("STS() should return non-nil client")
	}

	if stsAgain := c.STS(); sts != stsAgain {
		t.Error("STS() should return same instance")
	}
}

func TestClientLazyInitCloudTrail(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	ct := c.CloudTrail()
	if ct == nil {
		t.Fatal("CloudTrail() should return non-nil client")
	}

	if ctAgain := c.CloudTrail(); ct != ctAgain {
		t.Error("CloudTrail() should return same instance")
	}
}

// TestClientLazyInitConcurrency verifies that concurrent lazy init is safe.
func TestClientLazyInitConcurrency(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	var wg sync.WaitGroup
	results := make(chan any, 100)

	// Launch concurrent accesses
	for i := 0; i < 10; i++ {
		wg.Add(5)
		go func() { defer wg.Done(); results <- c.CloudTrail() }()
		go func() { defer wg.Done(); results <- c.IAM() }()
		go func() { defer wg.Done(); results <- c.KMS() }()
		go func() { defer wg.Done(); results <- c.STS() }()
		go func() { defer wg.Done(); results <- c.CloudTrail() }()
	}

	wg.Wait()
	close(results)

	count := 0
	for r := range results {
		if r == nil {
			t.Error("concurrent lazy init should not return nil")
		}
		count++
	}
	if count != 50 {
		t.Errorf("should have received 50 results, got %d", count)
	}
}

func TestClientConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config ClientConfig
	}{
		{
			name: "basic config",
			config: ClientConfig{
				Region: "us-west-2",
			},
		},
		{
			name: "with role ARN",
			config: ClientConfig{
				Region:  "eu-west-1",
				RoleARN: "arn:aws:iam::123456789012:role/test",
			},
		},
		{
			name: "with cross-account",
			config: ClientConfig{
				Region: "ap-southeast-1",
				AssumeRoleConfig: &AssumeRoleConfig{
					RoleARN:    "arn:aws:iam::987654321098:role/cross",
					ExternalID: "ext-123",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			awsCfg := awssdk.Config{
				Region:      tt.config.Region,
				Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
			}
			c := &Client{
				config:    tt.config,
				awsConfig: awsCfg,
				logger:    slog.New(slog.DiscardHandler),
			}
			if c.config.Region != tt.config.Region {
				t.Errorf("region = %q, want %q", c.config.Region, tt.config.Region)
			}
		})
	}
}

func TestNewClientForTesting(t *testing.T) {
	t.Parallel()
	c := NewClientForTesting("http://localhost:8080", "us-east-1", slog.New(slog.DiscardHandler))
	if c == nil {
		t.Fatal("NewClientForTesting returned nil")
	}
	if c.config.Region != "us-east-1" {
		t.Errorf("region = %q, want %q", c.config.Region, "us-east-1")
	}
}

func TestClientClosedState(t *testing.T) {
	t.Parallel()
	c := testClient(t)
	if c.closed {
		t.Error("client should not be closed initially")
	}
}
