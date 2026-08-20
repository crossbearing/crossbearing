package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// TestSignature_OutlivesTheKey pins the promise the whole evidence product
// rests on: a package stays verifiable after the key that signed it is gone.
//
// Keys are retired: a KMS key cannot move between AWS accounts, so an account
// migration ends one key and begins another, and any key can be scheduled for
// deletion. An operator archives the public half while the key lives. If
// deletion invalidated past signatures, that archive would be worthless and
// every package would rot on a schedule set by the key's lifetime rather than
// by its own contents.
//
// The test models that sequence. It signs, exports the public half to PEM the
// way `kms:GetPublicKey` plus archiving does, then DISCARDS the signer and the
// private key — nothing that could sign again survives the line marked below —
// and verifies from the archived bytes alone: no KMS, no AWS account, no
// network, no code of ours.
func TestSignature_OutlivesTheKey(t *testing.T) {
	payload := bytes.Repeat([]byte("evidence-that-must-outlive-its-key;"), 300)

	archivedPEM, bundle := func() ([]byte, SignatureBundle) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		s := NewKMSSigner(&fakeSignKMS{
			sign: func(in *kms.SignInput) (*kms.SignOutput, error) {
				sig, err := ecdsa.SignASN1(rand.Reader, key, in.Message)
				if err != nil {
					return nil, err
				}
				return &kms.SignOutput{Signature: sig}, nil
			},
		}, testKeyARN)

		b, err := s.Sign(context.Background(), payload)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		// Export the public half, as an operator archiving a key does.
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), b
	}()
	// ─── the key is gone from here down: no signer, no private key in scope ───

	block, _ := pem.Decode(archivedPEM)
	if block == nil {
		t.Fatal("archived PEM did not decode")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse archived public key: %v", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("archived key is %T, want *ecdsa.PublicKey", parsed)
	}

	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], bundle.Signature) {
		t.Fatal("a package signed by a now-deleted key failed to verify against its archived public half")
	}

	// Counterexample: a stranger's key of the same shape must not verify it,
	// or "it verified" would mean nothing.
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate stranger key: %v", err)
	}
	if ecdsa.VerifyASN1(&stranger.PublicKey, digest[:], bundle.Signature) {
		t.Error("a stranger's public key verified the signature")
	}

	// And the ARN in the bundle is a label, not a resolution step: nothing
	// above consulted it, and verification succeeded regardless.
	if bundle.KeyRef != testKeyARN {
		t.Errorf("KeyRef = %q, want %q recorded verbatim", bundle.KeyRef, testKeyARN)
	}
}

// TestDigestForAlgo_HashesToTheAlgorithmsWidth covers every mapped algorithm.
// KMS validates the digest length against the algorithm, so a wrong branch here
// is not a silent mismatch — it is a rejected sign call at the worst moment.
func TestDigestForAlgo_HashesToTheAlgorithmsWidth(t *testing.T) {
	payload := []byte("digest-width-fixture")
	sum256 := sha256.Sum256(payload)
	sum384 := sha512.Sum384(payload)
	sum512 := sha512.Sum512(payload)

	for _, tc := range []struct {
		algo kmstypes.SigningAlgorithmSpec
		want []byte
	}{
		{kmstypes.SigningAlgorithmSpecEcdsaSha256, sum256[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPssSha256, sum256[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, sum256[:]},
		{kmstypes.SigningAlgorithmSpecEcdsaSha384, sum384[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPssSha384, sum384[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384, sum384[:]},
		{kmstypes.SigningAlgorithmSpecEcdsaSha512, sum512[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPssSha512, sum512[:]},
		{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512, sum512[:]},
	} {
		t.Run(string(tc.algo), func(t *testing.T) {
			got, err := digestForAlgo(tc.algo, payload)
			if err != nil {
				t.Fatalf("digestForAlgo(%s): %v", tc.algo, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("digest = %x, want %x", got, tc.want)
			}
		})
	}
}

// TestDigestForAlgo_UnmappedAlgorithmErrors covers the algorithms KMS does not
// pre-hash this way. Returning an error is the point: a fallback to SHA-256
// would produce a digest KMS accepts for the wrong algorithm class, and the
// failure would surface as an unverifiable package rather than a failed sign.
func TestDigestForAlgo_UnmappedAlgorithmErrors(t *testing.T) {
	for _, algo := range []kmstypes.SigningAlgorithmSpec{
		"ED25519", "SM2DSA", "ML_DSA_SHAKE_256", "",
	} {
		if _, err := digestForAlgo(algo, []byte("x")); err == nil {
			t.Errorf("digestForAlgo(%q) returned no error; an unmapped algorithm must not fall back to a default hash", algo)
		}
	}
}

// TestKMSSigner_ClientError_WrapsAndReturnsNoBundle checks the failure path:
// when KMS refuses — key disabled, pending deletion, permission denied — the
// caller must get an error and a zero bundle, never a bundle that looks signed.
func TestKMSSigner_ClientError_WrapsAndReturnsNoBundle(t *testing.T) {
	sentinel := errors.New("KMSInvalidStateException: key is pending deletion")
	s := NewKMSSigner(&fakeSignKMS{
		sign: func(*kms.SignInput) (*kms.SignOutput, error) { return nil, sentinel },
	}, testKeyARN)

	bundle, err := s.Sign(context.Background(), []byte("payload"))
	if err == nil {
		t.Fatal("Sign returned no error when KMS refused")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the KMS cause (%%w): %v", err)
	}
	if !strings.Contains(err.Error(), "kms sign") {
		t.Errorf("error %q lacks the operation context", err)
	}
	if bundle.Signature != nil || bundle.KeyRef != "" || bundle.Algo != "" {
		t.Errorf("a failed sign returned a populated bundle: %+v", bundle)
	}
}

// TestNoopSigner_IsExplicitlyUnsignedNotPseudoSigned pins the distinction the
// pack format depends on: NoopSigner declines to sign, and must not emit
// anything a reader could mistake for a signature or a key reference.
func TestNoopSigner_IsExplicitlyUnsignedNotPseudoSigned(t *testing.T) {
	b, err := NoopSigner{}.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("NoopSigner.Sign: %v", err)
	}
	if len(b.Signature) != 0 {
		t.Errorf("Signature = %x, want empty", b.Signature)
	}
	if b.KeyRef != "" || b.Algo != "" {
		t.Errorf("bundle names a key or algorithm it did not use: %+v", b)
	}
}
