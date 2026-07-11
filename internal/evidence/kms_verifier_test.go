package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// fakeKMS is a minimal KMSVerifyAPI stub. The Verify hook lets each
// test decide what happens on a per-call basis.
type fakeKMS struct {
	verify func(*kms.VerifyInput) (*kms.VerifyOutput, error)
}

func (f *fakeKMS) Verify(_ context.Context, in *kms.VerifyInput, _ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	return f.verify(in)
}

// kmsTestFetcher is a minimal in-memory Fetcher so the verifier tests
// stay self-contained.
type kmsTestFetcher struct {
	bundles map[string][]byte
	err     error
}

func (f *kmsTestFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.bundles[ref]
	if !ok {
		return nil, ErrArtifactNotFound
	}
	return b, nil
}

const (
	testKeyARN = "arn:aws:kms:us-east-1:111111111111:key/abc"
	testBundle = "s3://b/k.sig"
)

func validSig() SignatureRef {
	return SignatureRef{
		KeyRef: testKeyARN,
		Algo:   "ECDSA_SHA_256",
		Bundle: testBundle,
	}
}

func TestKMSVerifier_HappyPath_PassesPayloadAndSignatureToKMS(t *testing.T) {
	payload := []byte("payload bytes")
	sigBytes := []byte{0x30, 0x44, 0x02, 0x20, 0xaa}

	var got *kms.VerifyInput
	v := NewKMSVerifier(&fakeKMS{
		verify: func(in *kms.VerifyInput) (*kms.VerifyOutput, error) {
			got = in
			return &kms.VerifyOutput{SignatureValid: true}, nil
		},
	}, &kmsTestFetcher{bundles: map[string][]byte{testBundle: sigBytes}})

	if err := v.Verify(context.Background(), payload, validSig()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got == nil {
		t.Fatal("kms.Verify was not called")
	}
	// The verifier pre-hashes to the algorithm's digest and submits
	// MessageType=DIGEST so payloads over the KMS 4096-byte RAW limit verify.
	wantDigest := sha256.Sum256(payload)
	if !bytes.Equal(got.Message, wantDigest[:]) {
		t.Errorf("message should be the SHA-256 digest of the payload, got % x", got.Message)
	}
	if string(got.Signature) != string(sigBytes) {
		t.Errorf("signature bytes not threaded: % x", got.Signature)
	}
	if got.MessageType != kmstypes.MessageTypeDigest {
		t.Errorf("MessageType: got %q, want Digest", got.MessageType)
	}
	if got.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 {
		t.Errorf("algo: got %q, want ECDSA_SHA_256", got.SigningAlgorithm)
	}
	if got.KeyId == nil || *got.KeyId != testKeyARN {
		t.Errorf("keyId not threaded: %v", got.KeyId)
	}
}

func TestKMSVerifier_KMSReportsInvalidSignature(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{
		verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return &kms.VerifyOutput{SignatureValid: false}, nil
		},
	}, &kmsTestFetcher{bundles: map[string][]byte{testBundle: {0xaa}}})

	err := v.Verify(context.Background(), []byte("p"), validSig())
	if err == nil {
		t.Fatal("expected error when SignatureValid=false")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestKMSVerifier_KMSInvalidSignatureException_FoldedIntoSentinel(t *testing.T) {
	apiErr := &smithy.GenericAPIError{
		Code:    "KMSInvalidSignatureException",
		Message: "Signature is invalid for the supplied message and key",
	}
	v := NewKMSVerifier(&fakeKMS{
		verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return nil, apiErr
		},
	}, &kmsTestFetcher{bundles: map[string][]byte{testBundle: {0xaa}}})

	err := v.Verify(context.Background(), []byte("p"), validSig())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("KMSInvalidSignatureException must fold to ErrSignatureInvalid; got %v", err)
	}
}

func TestKMSVerifier_TransientKMSError_BubblesUp(t *testing.T) {
	apiErr := &smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "rate exceeded",
	}
	v := NewKMSVerifier(&fakeKMS{
		verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return nil, apiErr
		},
	}, &kmsTestFetcher{bundles: map[string][]byte{testBundle: {0xaa}}})

	err := v.Verify(context.Background(), []byte("p"), validSig())
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("transient KMS errors must NOT fold to ErrSignatureInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "kms verify") {
		t.Errorf("error should be wrapped with kms verify prefix: %v", err)
	}
}

func TestKMSVerifier_BundleUnreachable(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{
		verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
			t.Fatal("kms.Verify must not be called when fetch fails")
			return nil, nil
		},
	}, &kmsTestFetcher{} /* no entries */)

	err := v.Verify(context.Background(), []byte("p"), validSig())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSignatureUnreachable) {
		t.Errorf("expected ErrSignatureUnreachable, got %v", err)
	}
}

func TestKMSVerifier_EmptyKeyRef_StructuralError(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{}, &kmsTestFetcher{})
	sig := validSig()
	sig.KeyRef = ""
	err := v.Verify(context.Background(), nil, sig)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid for empty KeyRef, got %v", err)
	}
}

func TestKMSVerifier_UnsupportedAlgo(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{}, &kmsTestFetcher{})
	sig := validSig()
	sig.Algo = "ED25519" // KMS does not support
	err := v.Verify(context.Background(), nil, sig)
	if !errors.Is(err, ErrUnsupportedAlgo) {
		t.Errorf("expected ErrUnsupportedAlgo, got %v", err)
	}
}

func TestKMSVerifier_EmptyBundleURL(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{}, &kmsTestFetcher{})
	sig := validSig()
	sig.Bundle = ""
	err := v.Verify(context.Background(), nil, sig)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid for empty bundle, got %v", err)
	}
}

func TestKMSVerifier_EmptyBundleBytes(t *testing.T) {
	v := NewKMSVerifier(&fakeKMS{}, &kmsTestFetcher{
		bundles: map[string][]byte{testBundle: {}},
	})
	err := v.Verify(context.Background(), nil, validSig())
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid for empty bundle bytes, got %v", err)
	}
}

func TestKMSVerifier_MissingFetcher_ReturnsConfigError(t *testing.T) {
	v := &KMSVerifier{Client: &fakeKMS{}, Fetcher: nil}
	err := v.Verify(context.Background(), nil, validSig())
	if err == nil {
		t.Fatal("expected error when Fetcher is nil")
	}
	if !strings.Contains(err.Error(), "Fetcher") {
		t.Errorf("error should name the Fetcher: %v", err)
	}
}

// TestKMSVerifier_PluggedIntoPolicyVerifier ties the layers together:
// PolicyVerifier delegates to KMSVerifier, and the rejection path
// surfaces the failure correctly.
func TestKMSVerifier_PluggedIntoPolicyVerifier_RejectsBadSignature(t *testing.T) {
	pol := TrustPolicy{
		AllowedAlgos:   []string{"ECDSA_SHA_256"},
		KeyRefPatterns: []string{"^arn:aws:kms:.+:111111111111:key/.+$"},
	}
	v := PolicyVerifier{
		Crypto: NewKMSVerifier(
			&fakeKMS{verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
				return &kms.VerifyOutput{SignatureValid: false}, nil
			}},
			&kmsTestFetcher{bundles: map[string][]byte{testBundle: {0xaa}}},
		),
	}
	res, err := v.Verify(context.Background(), []byte("p"),
		[]SignatureRef{validSig()}, pol)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Trusted {
		t.Error("structural pass + crypto fail must produce Trusted=false")
	}
	if res.Reason != "CryptoVerifyFailed" {
		t.Errorf("Reason: got %q, want CryptoVerifyFailed", res.Reason)
	}
}

func TestKMSVerifier_PluggedIntoPolicyVerifier_AcceptsValidSignature(t *testing.T) {
	pol := TrustPolicy{
		KeyRefPatterns: []string{"^arn:aws:kms:.+:111111111111:key/.+$"},
	}
	v := PolicyVerifier{
		Crypto: NewKMSVerifier(
			&fakeKMS{verify: func(_ *kms.VerifyInput) (*kms.VerifyOutput, error) {
				return &kms.VerifyOutput{SignatureValid: true}, nil
			}},
			&kmsTestFetcher{bundles: map[string][]byte{testBundle: {0xaa}}},
		),
	}
	res, err := v.Verify(context.Background(), []byte("p"),
		[]SignatureRef{validSig()}, pol)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Trusted {
		t.Errorf("expected trust: %+v", res)
	}
	if res.AcceptedKeyRef != testKeyARN {
		t.Errorf("AcceptedKeyRef: %v", res.AcceptedKeyRef)
	}
}
