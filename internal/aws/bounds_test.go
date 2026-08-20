package aws

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

// newTestClient builds a real client through NewClient, with credentials and
// IMDS pinned by env so config loading neither probes the network nor depends
// on the developer's AWS profile.
func newBoundsTestClient(t *testing.T) *Client {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	c, err := NewClient(context.Background(), ClientConfig{Region: "us-east-1"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestTransport_BoundsEveryConnectionPhase holds the transport to a bound on
// every connection phase. A custom http.Transport does not inherit
// http.DefaultTransport's timeouts, it inherits the zero value, which means
// "wait forever" — so every duration below must be non-zero or a black-holed
// endpoint hangs until the run deadline.
func TestTransport_BoundsEveryConnectionPhase(t *testing.T) {
	c := newBoundsTestClient(t)

	hc, ok := c.awsConfig.HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTPClient is %T, want *http.Client", c.awsConfig.HTTPClient)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", hc.Transport)
	}

	for _, f := range []struct {
		name string
		got  time.Duration
	}{
		{"TLSHandshakeTimeout", tr.TLSHandshakeTimeout},
		{"ResponseHeaderTimeout", tr.ResponseHeaderTimeout},
		{"ExpectContinueTimeout", tr.ExpectContinueTimeout},
		{"IdleConnTimeout", tr.IdleConnTimeout},
	} {
		if f.got <= 0 {
			t.Errorf("%s = %v; a zero value here means wait forever", f.name, f.got)
		}
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil: without it the transport dials with no timeout")
	}
	// Both are http.DefaultTransport behaviors a custom transport drops
	// silently. Losing Proxy breaks every customer behind an egress proxy.
	if tr.Proxy == nil {
		t.Error("Proxy is nil: HTTPS_PROXY/HTTP_PROXY would be ignored")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is false: a custom transport disables HTTP/2 unless it is set")
	}
}

// TestRetryer_BudgetSurvivesThrottling pins the retry budget. CloudTrail
// LookupEvents is rate-limited to 2 requests/second, so throttling is the
// expected path through a full ingest rather than an exceptional one, and the
// SDK's 3-attempt default is a coin flip on a long window.
func TestRetryer_BudgetSurvivesThrottling(t *testing.T) {
	c := newBoundsTestClient(t)
	if c.awsConfig.Retryer == nil {
		t.Fatal("no retryer configured on the shared config")
	}
	r := c.awsConfig.Retryer()

	if got := r.MaxAttempts(); got != maxAttempts {
		t.Errorf("MaxAttempts = %d, want %d", got, maxAttempts)
	}
	if maxAttempts <= 3 {
		t.Fatalf("maxAttempts = %d; the whole point is to exceed the SDK default of 3", maxAttempts)
	}

	throttle := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	if !r.IsErrorRetryable(throttle) {
		t.Error("a ThrottlingException is not retryable; the budget is unreachable for the error it exists for")
	}

	// Backoff must stay under the ceiling at every attempt, or the extra
	// attempts are spent sleeping past a realistic run deadline.
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		d, err := r.RetryDelay(attempt, throttle)
		if err != nil {
			t.Fatalf("RetryDelay(%d): %v", attempt, err)
		}
		if d < 0 || d > maxBackoff {
			t.Errorf("RetryDelay(%d) = %v, want within (0, %v]", attempt, d, maxBackoff)
		}
	}
}

// TestRetryer_DoesNotRetryARefusal guards the other direction: a retry budget
// that retries non-transient failures turns one AccessDenied into eight, which
// on a read-only audit is a burst of denied calls in the customer's own
// CloudTrail — noise the engine itself would then have to explain.
func TestRetryer_DoesNotRetryARefusal(t *testing.T) {
	r := newRetryer()
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
	if r.IsErrorRetryable(denied) {
		t.Error("AccessDeniedException is retryable; a permission failure must fail once, not eight times")
	}
}
