package aws

import (
	"log/slog"
	"sync"
	"testing"
	"unsafe"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func newTestClient() *Client {
	return &Client{
		config:    ClientConfig{Region: "us-east-1"},
		awsConfig: aws.Config{Region: "us-east-1"},
		logger:    slog.New(slog.DiscardHandler),
	}
}

func TestClient_Close(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	if c.Closed() {
		t.Fatal("client should not be closed before Close()")
	}

	// Initialize a few service clients via lazyInit accessors
	_ = c.CloudTrail()
	_ = c.IAM()
	_ = c.KMS()

	if c.cloudTrailClient == nil || c.iamClient == nil || c.kmsClient == nil {
		t.Fatal("service clients should be initialized after accessor calls")
	}

	c.Close()

	if !c.Closed() {
		t.Fatal("client should be closed after Close()")
	}

	// After Close, closedGuard returns true so accessors return nil.
	if c.IAM() != nil || c.KMS() != nil {
		t.Fatal("service accessors should return nil after Close()")
	}
}

func TestClient_CloseIdempotent(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	c.Close()
	c.Close() // second call should not panic

	if !c.Closed() {
		t.Fatal("client should remain closed after double Close()")
	}
}

func TestClient_ClosedDefault(t *testing.T) {
	t.Parallel()
	c := newTestClient()
	if c.Closed() {
		t.Fatal("new client should not be closed")
	}
}

func TestClient_CloseNilsAllClients(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	// Initialize every service client
	_ = c.IAM()
	_ = c.KMS()
	_ = c.STS()
	_ = c.CloudTrail()

	c.Close()

	// After Close, all accessors should return nil
	if c.IAM() != nil {
		t.Error("IAM() not nil after Close")
	}
	if c.KMS() != nil {
		t.Error("KMS() not nil after Close")
	}
	if c.STS() != nil {
		t.Error("STS() not nil after Close")
	}
	if c.CloudTrail() != nil {
		t.Error("CloudTrail() not nil after Close")
	}
}

func TestClient_LazyInitInitializesOnce(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	// Call CloudTrail() multiple times — should return the same instance
	s3a := c.CloudTrail()
	s3b := c.CloudTrail()
	if s3a != s3b {
		t.Error("CloudTrail() should return the same instance on repeated calls")
	}
	if s3a == nil {
		t.Error("CloudTrail() should not return nil on a live client")
	}
}

func TestClient_LazyInitMultipleServices(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	// Call multiple service accessors and verify they return stable, non-nil instances.
	iamA := c.IAM()
	iamB := c.IAM()
	if iamA != iamB || iamA == nil {
		t.Error("IAM() should return the same non-nil instance")
	}

	kmsA := c.KMS()
	kmsB := c.KMS()
	if kmsA != kmsB || kmsA == nil {
		t.Error("KMS() should return the same non-nil instance")
	}

	ctA := c.CloudTrail()
	ctB := c.CloudTrail()
	if ctA != ctB || ctA == nil {
		t.Error("CloudTrail() should return the same non-nil instance")
	}
}

func TestClient_ConcurrentAccessors(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	const goroutines = 50

	// Use unsafe.Pointer to capture the concrete pointer values for identity comparison.
	stsResults := make(chan unsafe.Pointer, goroutines)
	s3Results := make(chan unsafe.Pointer, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			stsResults <- unsafe.Pointer(c.STS())
			s3Results <- unsafe.Pointer(c.CloudTrail())
		}()
	}

	wg.Wait()
	close(stsResults)
	close(s3Results)

	var firstSTS unsafe.Pointer
	for ptr := range stsResults {
		if firstSTS == nil {
			firstSTS = ptr
		}
		if ptr != firstSTS {
			t.Fatal("STS() returned different instances across goroutines")
		}
	}

	var firstS3 unsafe.Pointer
	for ptr := range s3Results {
		if firstS3 == nil {
			firstS3 = ptr
		}
		if ptr != firstS3 {
			t.Fatal("CloudTrail() returned different instances across goroutines")
		}
	}

	if firstSTS == nil || firstS3 == nil {
		t.Fatal("service clients should not be nil")
	}
}

func TestClient_RegionAndConfig(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	if c.Region() != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got %q", c.Region())
	}

	cfg := c.Config()
	if cfg.Region != "us-east-1" {
		t.Errorf("expected config region 'us-east-1', got %q", cfg.Region)
	}
}

func TestClient_Logger(t *testing.T) {
	t.Parallel()
	c := newTestClient()
	if c.Logger() == nil {
		t.Error("Logger() should return a non-nil logger")
	}
}

func TestClient_AllServiceAccessorsReturnNonNil(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	accessors := map[string]any{
		"IAM":        c.IAM(),
		"KMS":        c.KMS(),
		"STS":        c.STS(),
		"CloudTrail": c.CloudTrail(),
	}

	for name, client := range accessors {
		if client == nil {
			t.Errorf("%s() returned nil on a live client", name)
		}
	}
}

func TestClient_CloseAndAccessors(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	// Initialize some accessors.
	_ = c.IAM()
	_ = c.KMS()
	_ = c.CloudTrail()

	c.Close()

	// After Close, all initialized accessors should return nil.
	if c.IAM() != nil {
		t.Error("IAM() should be nil after Close")
	}
	if c.KMS() != nil {
		t.Error("KMS() should be nil after Close")
	}
	if c.CloudTrail() != nil {
		t.Error("CloudTrail() should be nil after Close")
	}
}

func TestClient_UninitializedAccessorsAfterClose(t *testing.T) {
	t.Parallel()
	c := newTestClient()

	// Don't call any accessor before Close.
	c.Close()

	// After Close, closedGuard returns true so all accessors return nil,
	// regardless of whether they were initialized before Close.
	if c.KMS() != nil {
		t.Error("KMS() should return nil after Close")
	}
}
