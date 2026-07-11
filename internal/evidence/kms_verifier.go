package evidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// KMSVerifyAPI is the slice of the KMS client surface KMSVerifier
// uses. Defining it here mirrors KMSAPI on the signing side and lets
// tests inject a fake without spinning up KMS.
type KMSVerifyAPI interface {
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// KMSVerifier is the cryptographic-verification half of the trust
// chain that pairs with KMSSigner.
//
// Wire contract: the SignatureRef carries `KeyRef` (the AWS KMS key
// ARN), `Algo` (one of the KMS SigningAlgorithmSpec values like
// "ECDSA_SHA_256"), and `Bundle` (a fetchable URL pointing at the
// raw signature bytes — produced by the capture path as
// `<artifactRef>.sig`). KMSVerifier resolves Bundle through the
// shared Fetcher surface so the same scheme-set the artifact uses
// (s3 / oci / mem) works for signatures too.
//
// Failure modes:
//
//   - Bundle unfetchable                  → ErrSignatureUnreachable
//   - Algo not recognised by KMS          → ErrUnsupportedAlgo
//   - kms.Verify returns false / error    → ErrSignatureInvalid
//   - KeyRef empty                         → ErrSignatureInvalid
//
// Each is wrapped via fmt.Errorf so callers can switch on the
// sentinel via errors.Is and surface a stable reason string on
// rejection.
type KMSVerifier struct {
	Client  KMSVerifyAPI
	Fetcher Fetcher
}

// NewKMSVerifier constructs a Verifier-side companion to KMSSigner.
// Fetcher is required — without it the verifier cannot resolve the
// Bundle URL to raw bytes.
func NewKMSVerifier(c KMSVerifyAPI, fetcher Fetcher) *KMSVerifier {
	return &KMSVerifier{Client: c, Fetcher: fetcher}
}

// Sentinel errors KMSVerifier returns. Callers (PolicyVerifier) wrap
// these in CryptoVerifyFailed when surfacing a rejection.
var (
	// ErrSignatureUnreachable wraps the underlying fetch error when
	// the Bundle URL cannot be resolved. Treated as transient by
	// callers — the signature might be eventually consistent in
	// object storage.
	ErrSignatureUnreachable = errors.New("signature bundle unreachable")

	// ErrUnsupportedAlgo names an algo string the KMS client cannot
	// map. Permanent until the producer fixes the bundle.
	ErrUnsupportedAlgo = errors.New("kms verifier: algo not recognised")

	// ErrSignatureInvalid is returned when KMS rejects the signature
	// bytes for the given key + payload. Treated as a security
	// signal: tampered payload OR wrong key used at capture time.
	ErrSignatureInvalid = errors.New("signature verification failed")
)

// Verify implements Crypto.
func (v *KMSVerifier) Verify(ctx context.Context, payload []byte, sig SignatureRef) error {
	if sig.KeyRef == "" {
		return fmt.Errorf("%w: keyRef is empty", ErrSignatureInvalid)
	}
	if v.Fetcher == nil {
		return fmt.Errorf("KMSVerifier.Fetcher is required")
	}

	algo := kmstypes.SigningAlgorithmSpec(sig.Algo)
	if !isKnownAlgo(algo) {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgo, sig.Algo)
	}

	if sig.Bundle == "" {
		return fmt.Errorf("%w: signature bundle URL is empty", ErrSignatureInvalid)
	}
	signatureBytes, err := v.Fetcher.Fetch(ctx, sig.Bundle)
	if err != nil {
		return fmt.Errorf("%w: %v (bundle=%s)", ErrSignatureUnreachable, err, sig.Bundle)
	}
	if len(signatureBytes) == 0 {
		return fmt.Errorf("%w: signature bundle is empty", ErrSignatureInvalid)
	}

	// Pre-hash to the algorithm's digest and verify as MessageType=DIGEST,
	// symmetric with KMSSigner — so payloads over the KMS 4096-byte RAW limit
	// verify correctly. algo is already validated by isKnownAlgo above, so the
	// digest mapping always succeeds for accepted algorithms.
	digest, err := digestForAlgo(algo, payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedAlgo, err)
	}
	out, err := v.Client.Verify(ctx, &kms.VerifyInput{
		KeyId:            aws.String(sig.KeyRef),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		Signature:        signatureBytes,
		SigningAlgorithm: algo,
	})
	if err != nil {
		// AWS surfaces signature mismatches via KMSInvalidSignatureException
		// rather than a non-2xx body. Fold that into ErrSignatureInvalid
		// so the caller can distinguish it from a transient KMS outage
		// (which falls through and is treated as a verifier internal
		// error → caller treats it as Unreachable).
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "KMSInvalidSignatureException" {
			return fmt.Errorf("%w: %s", ErrSignatureInvalid, apiErr.ErrorMessage())
		}
		return fmt.Errorf("kms verify: %w", err)
	}
	if !out.SignatureValid {
		return fmt.Errorf("%w: kms reported SignatureValid=false", ErrSignatureInvalid)
	}
	return nil
}

// isKnownAlgo guards against operator-mistyped algo strings landing
// in the KMS API. The spec values come from the SDK enum; we accept
// the ones KMS commonly uses for asymmetric verification today.
// New algos (Ed25519, ML-DSA, SM2DSA) plug in by adding cases — kept
// minimal here to avoid claiming support we have not exercised.
func isKnownAlgo(a kmstypes.SigningAlgorithmSpec) bool {
	switch a {
	case kmstypes.SigningAlgorithmSpecEcdsaSha256,
		kmstypes.SigningAlgorithmSpecEcdsaSha384,
		kmstypes.SigningAlgorithmSpecEcdsaSha512,
		kmstypes.SigningAlgorithmSpecRsassaPssSha256,
		kmstypes.SigningAlgorithmSpecRsassaPssSha384,
		kmstypes.SigningAlgorithmSpecRsassaPssSha512,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return true
	case kmstypes.SigningAlgorithmSpecSm2dsa,
		kmstypes.SigningAlgorithmSpecMlDsaShake256,
		kmstypes.SigningAlgorithmSpecEd25519Sha512,
		kmstypes.SigningAlgorithmSpecEd25519PhSha512:
		// Defer support until someone wires + tests them. Operators
		// using these keys see ErrUnsupportedAlgo, which is actionable.
		return false
	}
	return false
}
