package aws

import (
	"context"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
)

// pinClientEnv pins credentials, IMDS and the CA bundle by env so config
// loading neither probes the network nor depends on the developer's AWS
// profile or proxy.
func pinClientEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CA_BUNDLE", "")
}

// newBoundsTestClient builds a real client through NewClient under a pinned env.
func newBoundsTestClient(t *testing.T) *Client {
	t.Helper()
	pinClientEnv(t)

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
	assertTransportBounded(t, newBoundsTestClient(t))
}

// TestTransport_AcceptsACABundle covers the customer behind a TLS-inspecting
// egress proxy, who sets AWS_CA_BUNDLE so the SDK trusts the proxy's CA. The
// SDK can only add that CA to a client built through BuildableClient; handed
// a bare http.Client it fails config loading, and the engine cannot start.
// The bundle must land in the transport without costing any phase its bound.
func TestTransport_AcceptsACABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(bundle, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	pinClientEnv(t)
	t.Setenv("AWS_CA_BUNDLE", bundle)
	c, err := NewClient(context.Background(), ClientConfig{Region: "us-east-1"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient with AWS_CA_BUNDLE set: %v", err)
	}
	t.Cleanup(c.Close)

	tr := assertTransportBounded(t, c)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("AWS_CA_BUNDLE is set but the transport carries no RootCAs: the proxy's CA would not be trusted")
	}
}

// assertTransportBounded checks every connection phase of the client's
// transport has a bound, and returns the transport for further checks.
func assertTransportBounded(t *testing.T, c *Client) *http.Transport {
	t.Helper()
	bc, ok := c.awsConfig.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("HTTPClient is %T, want *awshttp.BuildableClient: the SDK cannot apply a CA bundle to anything else", c.awsConfig.HTTPClient)
	}
	tr := bc.GetTransport()

	for _, f := range []struct {
		name string
		got  time.Duration
	}{
		{"Dialer.Timeout", bc.GetDialer().Timeout},
		{"TLSHandshakeTimeout", tr.TLSHandshakeTimeout},
		{"ResponseHeaderTimeout", tr.ResponseHeaderTimeout},
		{"ExpectContinueTimeout", tr.ExpectContinueTimeout},
		{"IdleConnTimeout", tr.IdleConnTimeout},
	} {
		if f.got <= 0 {
			t.Errorf("%s = %v; a zero value here means wait forever", f.name, f.got)
		}
	}
	if got := bc.GetDialer().Timeout; got != dialTimeout {
		t.Errorf("Dialer.Timeout = %v, want %v", got, dialTimeout)
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil: without it the transport dials with no timeout")
	}
	// Losing Proxy breaks every customer behind an egress proxy.
	if tr.Proxy == nil {
		t.Error("Proxy is nil: HTTPS_PROXY/HTTP_PROXY would be ignored")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 is false: a custom transport disables HTTP/2 unless it is set")
	}
	return tr
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
