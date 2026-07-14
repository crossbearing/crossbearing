package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeSignKMS is a minimal KMSAPI stub capturing the SignInput.
type fakeSignKMS struct {
	got  *kms.SignInput
	sign func(*kms.SignInput) (*kms.SignOutput, error)
}

func (f *fakeSignKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.got = in
	if f.sign != nil {
		return f.sign(in)
	}
	return &kms.SignOutput{Signature: []byte{0x30, 0x44}}, nil
}

// TestKMSSigner_LargePayload_SendsDigest verifies the headline fix: a payload
// far larger than the KMS 4096-byte RAW-message limit is reduced to its 32-byte
// SHA-256 digest and submitted as MessageType=DIGEST, so the sign call succeeds
// regardless of payload size.
func TestKMSSigner_LargePayload_SendsDigest(t *testing.T) {
	payload := bytes.Repeat([]byte("evidence-snapshot;"), 1500) // ~27 KB, well over 4096
	if len(payload) <= 4096 {
		t.Fatalf("test payload must exceed the KMS RAW limit, got %d bytes", len(payload))
	}

	fk := &fakeSignKMS{}
	s := NewKMSSigner(fk, testKeyARN)

	bundle, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if fk.got.MessageType != kmstypes.MessageTypeDigest {
		t.Errorf("MessageType: got %q, want Digest", fk.got.MessageType)
	}
	wantDigest := sha256.Sum256(payload)
	if !bytes.Equal(fk.got.Message, wantDigest[:]) {
		t.Errorf("message should be the 32-byte SHA-256 digest, got %d bytes", len(fk.got.Message))
	}
	if len(fk.got.Message) != sha256.Size {
		t.Errorf("digest length: got %d, want %d", len(fk.got.Message), sha256.Size)
	}
	if bundle.Algo != string(kmstypes.SigningAlgorithmSpecEcdsaSha256) {
		t.Errorf("algo: got %q, want ECDSA_SHA_256", bundle.Algo)
	}
}

// TestKMSSigner_BundleCarriesKeyARNAndAlgo verifies the bundle metadata the
// verifier needs to find the public key is threaded through.
func TestKMSSigner_BundleCarriesKeyARNAndAlgo(t *testing.T) {
	fk := &fakeSignKMS{}
	s := NewKMSSigner(fk, testKeyARN)

	bundle, err := s.Sign(context.Background(), []byte("x"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if bundle.KeyRef != testKeyARN {
		t.Errorf("KeyRef: got %q, want %q", bundle.KeyRef, testKeyARN)
	}
	if len(bundle.Signature) == 0 {
		t.Error("Signature bytes must be carried through from the KMS response")
	}
	if fk.got.KeyId == nil || *fk.got.KeyId != testKeyARN {
		t.Errorf("keyId not threaded: %v", fk.got.KeyId)
	}
}

// TestKMSSigner_MissingKeyARN_ReturnsConfigError mirrors the verifier's
// config-error tests: a signer without a key is a wiring bug, surfaced
// before any KMS call.
func TestKMSSigner_MissingKeyARN_ReturnsConfigError(t *testing.T) {
	s := NewKMSSigner(&fakeSignKMS{}, "")
	if _, err := s.Sign(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected error when KeyARN is empty")
	} else if !strings.Contains(err.Error(), "KeyARN") {
		t.Errorf("error should name the KeyARN: %v", err)
	}
}

// TestKMSSigner_UnsupportedAlgo_Errors verifies an algorithm with no digest
// mapping (e.g. Ed25519, which KMS does not pre-hash) is rejected rather than
// signed with a wrong digest.
func TestKMSSigner_UnsupportedAlgo_Errors(t *testing.T) {
	s := NewKMSSigner(&fakeSignKMS{}, testKeyARN)
	s.SigningAlgorithm = kmstypes.SigningAlgorithmSpecEd25519Sha512

	if _, err := s.Sign(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected an error for an unmapped signing algorithm, got nil")
	}
}

// testKeyARN is the KMS key every signer test signs under.
const testKeyARN = "arn:aws:kms:us-east-1:111111111111:key/abc"

// TestKMSSign_VerifiesWithStdlibCrypto proves the signer's contract end to end
// against real ECDSA P-256, with no help from any code of ours: the fake KMS
// signs exactly the bytes KMSSigner submits, and the resulting signature is
// checked with crypto/ecdsa directly.
//
// It is deliberately verified with the standard library rather than a Verifier
// of our own. The engine no longer HAS one — the evidence package is verified by
// the separate zero-dependency MIT tool in crossbearing/verify, which never
// imports this repo, and a round-trip through our own verifier could only ever
// prove the two halves agree with each other. Signing a payload larger than
// KMS's 4096-byte inline limit exercises the pre-digest / MessageType=DIGEST
// path, which is where the contract actually lives.
func TestKMSSign_VerifiesWithStdlibCrypto(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var signed []byte // the exact bytes KMSSigner asked KMS to sign
	s := NewKMSSigner(&fakeSignKMS{
		sign: func(in *kms.SignInput) (*kms.SignOutput, error) {
			signed = append([]byte(nil), in.Message...)
			sigBytes, err := ecdsa.SignASN1(rand.Reader, key, in.Message)
			if err != nil {
				return nil, err
			}
			return &kms.SignOutput{Signature: sigBytes}, nil
		},
	}, testKeyARN)

	payload := bytes.Repeat([]byte("round-trip-evidence;"), 500) // > 4096: the DIGEST path
	bundle, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The signer must have pre-hashed: KMS sees the digest, never the payload.
	want := sha256.Sum256(payload)
	if !bytes.Equal(signed, want[:]) {
		t.Fatalf("KMS was handed %d bytes; it must be handed the sha256 digest of the payload", len(signed))
	}
	if bundle.KeyRef != testKeyARN {
		t.Errorf("KeyRef = %q, want %q", bundle.KeyRef, testKeyARN)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, want[:], bundle.Signature) {
		t.Fatal("the signature does not verify against the payload digest")
	}

	// A tampered payload hashes differently and must not verify.
	tampered := sha256.Sum256(append([]byte("tamper:"), payload...))
	if ecdsa.VerifyASN1(&key.PublicKey, tampered[:], bundle.Signature) {
		t.Error("a tampered payload verified against the original signature")
	}
}
