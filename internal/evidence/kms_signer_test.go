package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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

// TestKMSSignVerify_RoundTrip exercises the full sign→verify loop with fakes
// that do real ECDSA P-256 crypto in place of KMS: the sign fake signs the
// digest KMSSigner submits, the bundle's signature bytes are staged behind
// the Fetcher (as the capture path would), and the verify fake checks the
// digest KMSVerifier submits against the same key pair. Proves the two
// halves agree on pre-hashing + MessageType=DIGEST end-to-end, and that a
// tampered payload is rejected.
func TestKMSSignVerify_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	s := NewKMSSigner(&fakeSignKMS{
		sign: func(in *kms.SignInput) (*kms.SignOutput, error) {
			sigBytes, err := ecdsa.SignASN1(rand.Reader, key, in.Message)
			if err != nil {
				return nil, err
			}
			return &kms.SignOutput{Signature: sigBytes}, nil
		},
	}, testKeyARN)

	payload := bytes.Repeat([]byte("round-trip-evidence;"), 500) // > 4096, exercises DIGEST path
	bundle, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Stage the detached signature where the verifier's Fetcher resolves
	// the Bundle URL, exactly as the capture path writes `<artifactRef>.sig`.
	v := NewKMSVerifier(&fakeKMS{
		verify: func(in *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return &kms.VerifyOutput{
				SignatureValid: ecdsa.VerifyASN1(&key.PublicKey, in.Message, in.Signature),
			}, nil
		},
	}, &kmsTestFetcher{bundles: map[string][]byte{testBundle: bundle.Signature}})

	ref := SignatureRef{KeyRef: bundle.KeyRef, Algo: bundle.Algo, Bundle: testBundle}
	if err := v.Verify(context.Background(), payload, ref); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}

	// A tampered payload hashes to a different digest and must fail.
	tampered := append([]byte("tamper:"), payload...)
	err = v.Verify(context.Background(), tampered, ref)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered payload: expected ErrSignatureInvalid, got %v", err)
	}
}
