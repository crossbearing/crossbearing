// Package evidence is the signing + verification half of the evidence
// pipeline: detached signatures over captured payloads, minted by a
// Signer at capture time and checked by a Verifier afterwards.
//
// The KMS-backed implementations (KMSSigner / KMSVerifier) talk to AWS
// KMS through narrow interface seams (KMSAPI / KMSVerifyAPI) so tests
// inject fakes without spinning up KMS.
package evidence

import (
	"context"
	"errors"
)

// SignatureRef points at a detached signature covering a payload. The
// producer does not verify at capture time — verification happens
// out-of-band via the Verifier, which records the outcome.
type SignatureRef struct {
	// KeyRef identifies the signing key, for example an AWS KMS key
	// ARN, "cosign://<key-id>" or "oidc://issuer=…,subject=…".
	KeyRef string

	// Bundle is the location of the serialized signature material.
	// For in-memory captures it may be inline base64; for production
	// it's an s3://... or oci://... URL.
	Bundle string

	// Algo names the signing algorithm, e.g. "ECDSA_SHA_256".
	Algo string
}

// Fetcher is the verifier-facing interface: given an artifact reference
// ("mem://...", "s3://...", "oci://..."), return the payload bytes. The
// production deployment wires an implementation that understands every
// scheme the capture service writes; tests wire an in-memory one.
type Fetcher interface {
	Fetch(ctx context.Context, artifactRef string) ([]byte, error)
}

// ErrArtifactNotFound is returned by a Fetcher when the referenced
// artifact does not exist in the backing store. The verifier maps this
// to Unreachable rather than a digest mismatch, since a missing
// artifact could be transient (storage being bootstrapped) or
// permanent (retention policy) — both warrant operator attention.
var ErrArtifactNotFound = errors.New("evidence artifact not found")

// ErrUnsupportedScheme is returned by a Fetcher that does not understand
// an artifactRef's scheme. Producers + verifiers must be deployed as a
// matched pair; a mismatch is surfaced with a clear error rather than
// silently re-fetched forever.
var ErrUnsupportedScheme = errors.New("unsupported artifact scheme")

// Signer signs an evidence payload and returns a SignatureBundle that the
// verifier can validate without trusting the capture service. Implementations:
//
//   - KMSSigner — calls AWS KMS Sign with a configured key. The bundle's
//     KeyRef is the key ARN; the verifier resolves the public key by ARN.
//   - NoopSigner — produces a zero-valued bundle. Used when the operator
//     intentionally runs without signing (dev environments, bootstrap).
//   - Future: cosign keyless via Fulcio; the SignatureBundle shape is
//     deliberately compatible with the cosign envelope format.
//
// The Signer is invoked synchronously inside capture; failures abort the
// capture so the operator never persists an unsigned-but-claimed-signed
// artifact.
type Signer interface {
	Sign(ctx context.Context, payload []byte) (SignatureBundle, error)
}

// SignatureBundle carries a detached signature plus the metadata a
// verifier needs to find the public key.
type SignatureBundle struct {
	// Signature is the raw signature bytes. The bundle's encoding is
	// algorithm-defined: ECDSA P-256 produces an ASN.1 SEQUENCE; RSA
	// PKCS#1v1.5 produces a fixed-width byte slice.
	Signature []byte

	// KeyRef identifies the public key. For KMS, this is the key ARN.
	// For cosign keyless, the Fulcio-issued certificate.
	KeyRef string

	// Algo names the signature algorithm in cosign-compatible form
	// (e.g. "ECDSA_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256").
	Algo string
}

// NoopSigner returns an empty SignatureBundle. Operators that have not yet
// configured KMS can still use a durable storage backend; the verifier
// will accept capture artifacts on digest match alone, leaving signature
// verification as a no-op.
type NoopSigner struct{}

// Sign implements Signer.
func (NoopSigner) Sign(_ context.Context, _ []byte) (SignatureBundle, error) {
	return SignatureBundle{}, nil
}
