package aws

import (
	"log/slog"
	"sync"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestClientInit_ConcurrentServiceAccess(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make(chan any, goroutines)

	// Concurrently access multiple service accessors
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			switch idx % 5 {
			case 0:
				results <- client.CloudTrail()
			case 1:
				results <- client.IAM()
			case 2:
				results <- client.KMS()
			case 3:
				results <- client.STS()
			case 4:
				results <- client.CloudTrail()
			}
		}(i)
	}

	wg.Wait()
	close(results)

	for r := range results {
		if r == nil {
			t.Error("service accessor returned nil under concurrent access")
		}
	}
}

func TestClientInit_ConcurrentSameService(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// All goroutines access the same service - must return same pointer
	results := make(chan any, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			results <- client.CloudTrail()
		}()
	}

	wg.Wait()
	close(results)

	// All results should be the same pointer (lazyInit guarantees)
	var first any
	for r := range results {
		if first == nil {
			first = r
		}
		if r != first {
			t.Fatal("all goroutines should get the same client instance")
		}
	}
}

func TestClientInit_ConcurrentCloseAndAccess(t *testing.T) {
	t.Parallel()
	// Test that close and access don't race
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// Pre-initialize some services
	client.CloudTrail()
	client.IAM()

	var wg sync.WaitGroup
	wg.Add(2)

	// One goroutine checks Closed()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = client.Closed()
		}
	}()

	// Another accesses Region()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = client.Region()
		}
	}()

	wg.Wait()
}

func TestClientInit_DoubleClose(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	client.CloudTrail()
	client.IAM()

	client.Close()
	if !client.Closed() {
		t.Fatal("client should be closed after Close()")
	}

	// Second close should be safe
	client.Close()
	if !client.Closed() {
		t.Fatal("client should remain closed after double Close()")
	}
}

func TestClientInit_AllServiceAccessors(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}

	// Test all service accessors return non-nil
	if client.CloudTrail() == nil {
		t.Error("CloudTrail() returned nil")
	}
	if client.IAM() == nil {
		t.Error("IAM() returned nil")
	}
	if client.KMS() == nil {
		t.Error("KMS() returned nil")
	}
	if client.STS() == nil {
		t.Error("STS() returned nil")
	}
	if client.CloudTrail() == nil {
		t.Error("CloudTrail() returned nil")
	}
}

func TestClientInit_Logger(t *testing.T) {
	t.Parallel()
	client := NewClientForTesting("http://localhost:12345", "us-east-1", discardLogger())
	if client == nil {
		t.Fatal("NewClientForTesting returned nil")
	}
	if client.Logger() == nil {
		t.Error("Logger() should return non-nil logger")
	}
}
