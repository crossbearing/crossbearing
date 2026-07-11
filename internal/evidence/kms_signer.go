package evidence

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// digestForAlgo hashes payload with the hash function the given KMS signing
// algorithm expects, so the message can be submitted as MessageType=DIGEST on
// both the sign and verify paths.
//
// KMS caps a MessageType=RAW message at 4096 bytes; evidence payloads
// routinely exceed that, so signing the raw bytes would fail. Pre-hashing to
// a DIGEST lifts the limit and yields an identical signature — KMS would hash
// the same way internally for RAW. The digest length must match the
// algorithm's hash (SHA-256→32, 384→48, 512→64), which KMS validates.
//
// Only the ECDSA_* and RSASSA_* SHA-256/384/512 algorithms are mapped — exactly
// the set isKnownAlgo accepts on the verify side. Algorithms KMS does not
// pre-hash this way (Ed25519, SM2DSA, ML-DSA) are unsupported and return an
// error rather than a silently-wrong digest.
func digestForAlgo(algo kmstypes.SigningAlgorithmSpec, payload []byte) ([]byte, error) {
	switch algo {
	case kmstypes.SigningAlgorithmSpecEcdsaSha256,
		kmstypes.SigningAlgorithmSpecRsassaPssSha256,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		h := sha256.Sum256(payload)
		return h[:], nil
	case kmstypes.SigningAlgorithmSpecEcdsaSha384,
		kmstypes.SigningAlgorithmSpecRsassaPssSha384,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		h := sha512.Sum384(payload)
		return h[:], nil
	case kmstypes.SigningAlgorithmSpecEcdsaSha512,
		kmstypes.SigningAlgorithmSpecRsassaPssSha512,
		kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		h := sha512.Sum512(payload)
		return h[:], nil
	default:
		return nil, fmt.Errorf("no digest mapping for signing algorithm %q", algo)
	}
}

// KMSAPI is the slice of the KMS client surface KMSSigner uses.
type KMSAPI interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner signs evidence payloads via AWS KMS. The KeyARN identifies an
// asymmetric signing key; verifiers resolve the public key by ARN through
// kms:GetPublicKey, so the bundle is decoupled from the capture service's
// trust state.
//
// SigningAlgorithm defaults to ECDSA_SHA_256 when empty. Operators using
// RSA keys must override.
type KMSSigner struct {
	Client           KMSAPI
	KeyARN           string
	SigningAlgorithm kmstypes.SigningAlgorithmSpec
}

// NewKMSSigner constructs a Signer backed by AWS KMS.
func NewKMSSigner(c KMSAPI, keyARN string) *KMSSigner {
	return &KMSSigner{
		Client:           c,
		KeyARN:           keyARN,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}
}

// Sign implements Signer. The payload is pre-hashed to the algorithm's digest
// and submitted as MessageType=DIGEST, so payloads larger than the KMS 4096-byte
// RAW-message limit sign correctly (and identically to how KMS would hash them).
func (s *KMSSigner) Sign(ctx context.Context, payload []byte) (SignatureBundle, error) {
	if s.KeyARN == "" {
		return SignatureBundle{}, fmt.Errorf("KMSSigner.KeyARN is required")
	}
	algo := s.SigningAlgorithm
	if algo == "" {
		algo = kmstypes.SigningAlgorithmSpecEcdsaSha256
	}
	digest, err := digestForAlgo(algo, payload)
	if err != nil {
		return SignatureBundle{}, fmt.Errorf("kms sign: %w", err)
	}
	out, err := s.Client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.KeyARN),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: algo,
	})
	if err != nil {
		return SignatureBundle{}, fmt.Errorf("kms sign: %w", err)
	}
	return SignatureBundle{
		Signature: out.Signature,
		KeyRef:    s.KeyARN,
		Algo:      string(algo),
	}, nil
}
