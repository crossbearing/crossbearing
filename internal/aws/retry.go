package aws

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
)

// Timeouts bounding a single HTTP attempt. These are per-phase, not per-call:
// the SDK may retry an attempt that trips one of them, and the caller's context
// still bounds the whole operation.
//
// The values are much shorter than the run deadline. A read-only audit has no
// partial-success state to protect, so failing a stuck attempt fast and
// retrying it beats holding the run open on a connection that has gone quiet.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// Retry budget. The SDK's default is 3 attempts, which is tuned for APIs that
// throttle rarely. CloudTrail LookupEvents — the call this engine makes most —
// is rate-limited to 2 requests per second, so on any account with real history
// throttling is the EXPECTED path through a full ingest, not an exceptional
// one. Three attempts is a coin flip on a long window; the fourth page failing
// aborts the whole report and loses the twenty pages already read.
//
// retry.NewStandard already retries throttling and transient errors with
// exponential backoff and full jitter, so what is tuned here is only the budget:
// more attempts, and a backoff ceiling low enough that the extra attempts are
// actually spent inside a realistic run deadline rather than sleeping past it.
const (
	maxAttempts = 8
	maxBackoff  = 20 * time.Second
)

// newRetryer builds the retryer used by every service client on the shared
// config. Kept as a named function rather than an inline closure so the tests
// can assert the budget directly — an untested retry policy is a guess.
func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = maxAttempts
		o.MaxBackoff = maxBackoff
	})
}
