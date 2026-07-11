package aws

import (
	"testing"
)

func TestSTS_ClientLazyInit(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// STS() should lazily create a client
	if client.STS() == nil {
		t.Error("STS() should return non-nil client")
	}
}

func TestSTS_ClientAfterClose(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// Initialize STS
	if client.STS() == nil {
		t.Fatal("STS() should return non-nil client")
	}

	// Close the client
	client.Close()
	if !client.Closed() {
		t.Fatal("client should report closed after Close()")
	}

	// STS() returns nil after close since stsClient was nilled and closed is true
	if client.STS() != nil {
		t.Error("STS() should return nil after Close()")
	}
}

func TestSTS_AssumeRoleClient(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// AssumeRoleClient creates a new client with assumed role credentials
	assumedClient := client.AssumeRoleClient(
		"arn:aws:iam::123456789012:role/target-role",
		"test-session",
	)
	if assumedClient == nil {
		t.Fatal("AssumeRoleClient returned nil")
	}

	// The assumed client should have its own STS client
	if assumedClient.STS() == nil {
		t.Error("assumed client STS() should return non-nil client")
	}
}

func TestSTS_Region(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "eu-west-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}
	if client.Region() != "eu-west-1" {
		t.Errorf("Region() = %q, want %q", client.Region(), "eu-west-1")
	}
}

func TestSTS_Config(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-west-2", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	cfg := client.Config()
	if cfg.Region != "us-west-2" {
		t.Errorf("Config().Region = %q, want %q", cfg.Region, "us-west-2")
	}
}

func TestSTS_Logger(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}
	if client.Logger() == nil {
		t.Error("Logger() should return non-nil logger")
	}
}

func TestSTS_ClosedInitiallyFalse(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}
	if client.Closed() {
		t.Error("newly created client should not be closed")
	}
}

func TestSTS_RegionTableDriven(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		region string
	}{
		{name: "us-east-1", region: "us-east-1"},
		{name: "us-west-2", region: "us-west-2"},
		{name: "eu-west-1", region: "eu-west-1"},
		{name: "eu-central-1", region: "eu-central-1"},
		{name: "ap-southeast-1", region: "ap-southeast-1"},
		{name: "ap-northeast-1", region: "ap-northeast-1"},
		{name: "sa-east-1", region: "sa-east-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := NewClientForTesting("http://localhost:12345", tt.region, discardLogger())
			if client == nil {
				t.Fatal("NewClientForTesting returned nil")
			}
			if client.Region() != tt.region {
				t.Errorf("Region() = %q, want %q", client.Region(), tt.region)
			}
			if client.Config().Region != tt.region {
				t.Errorf("Config().Region = %q, want %q", client.Config().Region, tt.region)
			}
		})
	}
}

func TestSTS_CloseIdempotent(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// Close multiple times should not panic
	client.Close()
	if !client.Closed() {
		t.Error("client should be closed after Close()")
	}
	client.Close()
	if !client.Closed() {
		t.Error("client should remain closed after second Close()")
	}
}

func TestSTS_STSIdempotent(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// Multiple calls to STS() should return the same instance
	sts1 := client.STS()
	sts2 := client.STS()
	if sts1 == nil || sts2 == nil {
		t.Fatal("STS() should return non-nil clients")
	}
	if sts1 != sts2 {
		t.Error("STS() should return the same instance on repeated calls")
	}
}
