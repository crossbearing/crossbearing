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
)

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
