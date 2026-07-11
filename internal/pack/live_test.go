package pack

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	kmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	awsint "github.com/crossbearing/crossbearing/internal/aws"
	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/evidence"
)

// TestLive_KMSSignAndVerify validates the signing path against real KMS:
// a package signed through evidence.KMSSigner must verify through a raw
// kms:Verify call on the same digest — the property the MIT verifier CLI
// will rely on. Optionally (CROSSBEARING_AEP), an already-emitted package
// file is verified the same way, proving artifacts on disk re-derive to
// the exact bytes their signature covers.
//
//	CROSSBEARING_KMS_KEY=<arn> AWS_PROFILE=... AWS_REGION=... \
//	  go test ./internal/pack -run TestLive -v
func TestLive_KMSSignAndVerify(t *testing.T) {
	keyARN := os.Getenv("CROSSBEARING_KMS_KEY")
	if keyARN == "" {
		t.Skip("set CROSSBEARING_KMS_KEY to a SIGN_VERIFY key ARN to run")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-west-2"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := awsint.NewClient(ctx, awsint.ClientConfig{Region: region}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	verify := func(t *testing.T, p *Package) {
		t.Helper()
		if p.Signature == nil {
			t.Fatal("package is unsigned")
		}
		payload, err := p.Payload()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		out, err := client.KMS().Verify(ctx, &kmssdk.VerifyInput{
			KeyId:            &p.Signature.KeyRef,
			Message:          digest[:],
			MessageType:      kmstypes.MessageTypeDigest,
			Signature:        p.Signature.Signature,
			SigningAlgorithm: kmstypes.SigningAlgorithmSpec(p.Signature.Algo),
		})
		if err != nil {
			t.Fatalf("kms verify: %v", err)
		}
		if !out.SignatureValid {
			t.Fatal("KMS reports the signature INVALID")
		}
	}

	t.Run("round-trip", func(t *testing.T) {
		p, err := Build(Input{
			Report: &corroborate.Report{
				From: time.Now().Add(-time.Hour).UTC(),
				To:   time.Now().UTC(),
				Findings: []corroborate.Finding{{
					Kind: corroborate.Corroborated, SessionID: "live-test",
					Why: "live sign/verify round-trip fixture",
				}},
			},
			GeneratedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Sign(ctx, evidence.NewKMSSigner(client.KMS(), keyARN)); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		verify(t, p)
		t.Logf("signed and verified via %s", keyARN)

		// A tampered payload must fail: flip one finding and re-verify.
		p.Findings[0].Finding.Why = "tampered"
		payload, _ := p.Payload()
		digest := sha256.Sum256(payload)
		out, err := client.KMS().Verify(ctx, &kmssdk.VerifyInput{
			KeyId:            &p.Signature.KeyRef,
			Message:          digest[:],
			MessageType:      kmstypes.MessageTypeDigest,
			Signature:        p.Signature.Signature,
			SigningAlgorithm: kmstypes.SigningAlgorithmSpec(p.Signature.Algo),
		})
		// KMS signals invalid via error OR SignatureValid=false depending on path.
		if err == nil && out.SignatureValid {
			t.Fatal("KMS verified a tampered payload")
		}
	})

	t.Run("emitted artifact", func(t *testing.T) {
		path := os.Getenv("CROSSBEARING_AEP")
		if path == "" {
			t.Skip("set CROSSBEARING_AEP to a signed package file to verify it")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var p Package
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain(&p); err != nil {
			t.Fatalf("chain: %v", err)
		}
		verify(t, &p)
		t.Logf("artifact %s: chain + signature verified (%d findings)", path, p.Chain.Length)
	})
}
