package evidence

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Verifier checks that a payload's signatures satisfy a trust policy.
// It pairs with the Signer interface — Signer mints bundles at capture
// time, Verifier accepts or rejects them at verify time.
//
// Implementations:
//
//   - NoopVerifier — accepts everything. Used in dev environments and
//     as the default when no policy is configured. Preserves the
//     "digest match alone is enough" behaviour.
//
//   - PolicyVerifier — applies a TrustPolicy structurally: allowed
//     algos, allowed keyRef patterns, "unsigned-allowed" flag.
//     Cryptographic verification of the actual signature bytes is
//     delegated to the Crypto seam (today: KMSVerifier).
//
// The Verifier is invoked after the digest comparison has passed.
// Result.Trusted gates acceptance; Result.Reason gives callers a
// stable identifier for the rejection class.
type Verifier interface {
	Verify(ctx context.Context, payload []byte, signatures []SignatureRef, policy TrustPolicy) (VerificationResult, error)
}

// VerificationResult is the outcome of a Verifier.Verify call. The
// reason / message fields are surfaced verbatim to operators so the
// text must be actionable.
type VerificationResult struct {
	// Trusted is true when at least one signature satisfies the
	// trust policy. False when no signature was found (and the
	// policy disallows unsigned), all signatures failed, or the
	// policy itself rejected the candidate signing identity.
	Trusted bool

	// Reason is a short identifier — "TrustedKeyRef",
	// "NoSignatures", "AlgoNotAllowed", "KeyRefNotAllowed",
	// "MalformedBundle". Populated for both Trusted=true and
	// Trusted=false outcomes so the audit log can correlate.
	Reason string

	// Message is human-readable detail.
	Message string

	// AcceptedKeyRef names the keyRef that satisfied the policy
	// when Trusted=true. Empty otherwise. Useful for the audit
	// trail — operators want to know which key actually matched.
	AcceptedKeyRef string
}

// TrustPolicy declares which signatures the verifier accepts. The
// zero value is a permissive policy — empty allow-lists match
// nothing structurally, but UnsignedAllowed defaults to true via
// TrustPolicyDefault so a fresh deployment does not lock its
// evidence behind a policy nobody has authored yet.
type TrustPolicy struct {
	// AllowedAlgos is the closed set of `algo` values the verifier
	// accepts. Empty means any algo passes (structural check only).
	AllowedAlgos []string

	// KeyRefPatterns is a list of regular expressions; a
	// signature's KeyRef must match at least one to be accepted.
	// Patterns use Go's regexp syntax. Empty means any keyRef passes.
	//
	// Typical patterns:
	//   ^arn:aws:kms:[^:]+:[0-9]{12}:key/[a-f0-9-]+$
	//   ^cosign://gha-prod/.*$
	//   ^oidc://issuer=https://token\.actions\.githubusercontent\.com,subject=.*$
	KeyRefPatterns []string

	// UnsignedAllowed lets an empty signatures[] satisfy the policy.
	// Defaults to true via TrustPolicyDefault — local-dev captures
	// are legitimately unsigned. Production trust policies should
	// set this to false explicitly.
	UnsignedAllowed bool
}

// TrustPolicyDefault returns the permissive default — accepts any
// algo, any keyRef, and unsigned envelopes. Callers reach for this
// when no operator-configured policy is loaded so the "digest match
// is enough" behaviour is preserved.
func TrustPolicyDefault() TrustPolicy {
	return TrustPolicy{UnsignedAllowed: true}
}

// NoopVerifier accepts every signature. Used when the operator
// intentionally runs without a trust policy (dev environments,
// bootstrap). Callers treat Trusted=true with Reason="NoopVerifier"
// the same as a real Trusted=true — the audit log records the
// distinction via Reason.
type NoopVerifier struct{}

// Verify implements Verifier.
func (NoopVerifier) Verify(_ context.Context, _ []byte, _ []SignatureRef, _ TrustPolicy) (VerificationResult, error) {
	return VerificationResult{
		Trusted: true,
		Reason:  "NoopVerifier",
		Message: "no trust policy configured; signatures accepted as-is",
	}, nil
}

// SignatureEnforcer is implemented by verifiers that perform real cryptographic
// verification. Callers consult it to choose a fail-closed default trust
// policy (unsigned disallowed) when no operator TrustPolicy is authored: if
// signing is configured, an unauthored policy must not silently accept
// unsigned evidence.
type SignatureEnforcer interface {
	EnforcesSignatures() bool
}

// EnforcesSignatures reports whether this verifier performs cryptographic
// verification. A PolicyVerifier enforces only when a Crypto backend is wired;
// a structural-only verifier (Crypto nil) does not, so it does not flip the
// default policy to fail-closed.
func (v PolicyVerifier) EnforcesSignatures() bool {
	return v.Crypto != nil
}

// PolicyVerifier implements the structural side of trust: algo +
// keyRef matching plus the unsigned-allowed flag. Cryptographic
// verification of the actual signature bytes is delegated to the
// underlying Crypto implementation (nil → structural-only).
//
// When Crypto is nil the verifier accepts any signature whose
// KeyRef + Algo match the policy — useful as a stepping stone
// while the cosign / KMS Verify integrations are wired. When
// Crypto is non-nil the structural check still runs first; only
// signatures that pass it are handed to Crypto.Verify for actual
// signature-bytes verification.
type PolicyVerifier struct {
	// Crypto, if non-nil, performs cryptographic verification
	// against the payload + signature bundle. Nil means
	// structural-only ("the keyRef looks right; trust it").
	Crypto Crypto
}

// Crypto is the cryptographic verification surface PolicyVerifier
// delegates to. Implementations: KMSVerifier (AWS KMS Verify API);
// future: CosignVerifier (Fulcio + Rekor). Callers are wired against
// the interface so new backends plug in without touching them.
type Crypto interface {
	// Verify checks `signature` is a valid signature over `payload`
	// using the algorithm + key identified by keyRef + algo.
	// Returns nil on success; an error names the failure mode
	// (key not found, signature does not match, malformed bundle).
	Verify(ctx context.Context, payload []byte, sig SignatureRef) error
}

// Verify implements Verifier.
//
// Decision tree:
//
//  1. No signatures present: Trusted = policy.UnsignedAllowed.
//  2. For each signature: structural match against AllowedAlgos +
//     KeyRefPatterns. Reject when none match.
//  3. (If Crypto is non-nil) hand the structurally-valid
//     signatures to Crypto.Verify. Any one that returns nil
//     produces Trusted=true.
//
// Multi-signature semantics: any one good signature is enough.
// Operators rotate keys by adding the new key's signature
// alongside the old; the verifier accepts the artifact while
// either is in the allow-list.
func (v PolicyVerifier) Verify(ctx context.Context, payload []byte, signatures []SignatureRef, policy TrustPolicy) (VerificationResult, error) {
	if len(signatures) == 0 {
		if policy.UnsignedAllowed {
			return VerificationResult{
				Trusted: true,
				Reason:  "UnsignedAllowed",
				Message: "envelope is unsigned; trust policy permits unsigned artifacts",
			}, nil
		}
		return VerificationResult{
			Trusted: false,
			Reason:  "NoSignatures",
			Message: "envelope is unsigned and trust policy requires a signature",
		}, nil
	}

	var lastReason, lastMessage string
	for i, sig := range signatures {
		if reason, msg, ok := matchPolicy(sig, policy); !ok {
			lastReason = reason
			lastMessage = fmt.Sprintf("signature[%d]: %s", i, msg)
			continue
		}
		// Structural match. If a Crypto verifier is configured,
		// run it; otherwise accept on structural match alone.
		if v.Crypto != nil {
			if err := v.Crypto.Verify(ctx, payload, sig); err != nil {
				lastReason = "CryptoVerifyFailed"
				lastMessage = fmt.Sprintf("signature[%d] (keyRef=%s): %v", i, sig.KeyRef, err)
				continue
			}
		}
		return VerificationResult{
			Trusted:        true,
			Reason:         "TrustedKeyRef",
			Message:        fmt.Sprintf("signature[%d] (keyRef=%s) matches trust policy", i, sig.KeyRef),
			AcceptedKeyRef: sig.KeyRef,
		}, nil
	}

	if lastReason == "" {
		// Defensive — every signature was rejected but we never
		// recorded a reason. Should not happen given matchPolicy
		// returns one; keep a safety net.
		lastReason = "NoTrustedSignature"
		lastMessage = "no signature in the envelope satisfied the trust policy"
	}
	return VerificationResult{
		Trusted: false,
		Reason:  lastReason,
		Message: lastMessage,
	}, nil
}

// matchPolicy checks a single signature against the policy's
// allow-lists. Returns (reason, message, ok) — when ok=false,
// reason names the rejection class. matchPolicy never errors;
// "the policy disallows this" is a legitimate result, not an
// error condition.
func matchPolicy(sig SignatureRef, policy TrustPolicy) (string, string, bool) {
	if len(policy.AllowedAlgos) > 0 {
		if !contains(policy.AllowedAlgos, sig.Algo) {
			return "AlgoNotAllowed",
				fmt.Sprintf("algo %q not in allowed-algos %v", sig.Algo, policy.AllowedAlgos),
				false
		}
	}
	if len(policy.KeyRefPatterns) > 0 {
		matched := false
		for _, pat := range policy.KeyRefPatterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				// A malformed policy pattern is an operator
				// configuration bug, not a per-signature failure.
				// We surface it as the reason for THIS signature
				// so the operator sees it in the rejection detail.
				return "MalformedPolicy",
					fmt.Sprintf("keyRef-pattern %q is not valid regex: %v", pat, err),
					false
			}
			if re.MatchString(sig.KeyRef) {
				matched = true
				break
			}
		}
		if !matched {
			return "KeyRefNotAllowed",
				fmt.Sprintf("keyRef %q does not match any allowed pattern", sig.KeyRef),
				false
		}
	}
	if sig.KeyRef == "" && sig.Algo == "" && len(sig.Bundle) == 0 {
		return "MalformedBundle",
			"signature bundle has empty keyRef, algo, and bundle",
			false
	}
	return "", "", true
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// SummariseTrustPolicy renders a TrustPolicy as a one-line
// human-readable summary, suitable for status / log messages.
// Avoids dumping every regex pattern verbatim — the operator can
// read the policy source if they want the full rules.
func SummariseTrustPolicy(p TrustPolicy) string {
	parts := []string{}
	if len(p.AllowedAlgos) > 0 {
		parts = append(parts, fmt.Sprintf("algos=[%s]", strings.Join(p.AllowedAlgos, ",")))
	}
	if len(p.KeyRefPatterns) > 0 {
		parts = append(parts, fmt.Sprintf("keyRefs=%d patterns", len(p.KeyRefPatterns)))
	}
	if p.UnsignedAllowed {
		parts = append(parts, "unsigned=allowed")
	} else {
		parts = append(parts, "unsigned=denied")
	}
	if len(parts) == 0 {
		return "trust policy: empty (permissive)"
	}
	return "trust policy: " + strings.Join(parts, " ")
}
