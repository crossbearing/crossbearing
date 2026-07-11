package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func sig(keyRef, algo string, bundle string) SignatureRef {
	return SignatureRef{KeyRef: keyRef, Algo: algo, Bundle: bundle}
}

func TestNoopVerifier_AcceptsEverything(t *testing.T) {
	res, err := NoopVerifier{}.Verify(context.Background(), nil, nil, TrustPolicy{})
	if err != nil {
		t.Fatalf("noop verifier returned error: %v", err)
	}
	if !res.Trusted || res.Reason != "NoopVerifier" {
		t.Errorf("noop verifier should always trust: %+v", res)
	}
}

func TestPolicyVerifier_NoSignatures_UnsignedAllowed(t *testing.T) {
	v := PolicyVerifier{}
	res, err := v.Verify(context.Background(), nil, nil, TrustPolicy{UnsignedAllowed: true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Trusted || res.Reason != "UnsignedAllowed" {
		t.Errorf("expected unsigned-allowed: %+v", res)
	}
}

func TestPolicyVerifier_NoSignatures_UnsignedDenied(t *testing.T) {
	v := PolicyVerifier{}
	res, err := v.Verify(context.Background(), nil, nil, TrustPolicy{UnsignedAllowed: false})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Trusted {
		t.Error("expected denial when policy requires signature")
	}
	if res.Reason != "NoSignatures" {
		t.Errorf("reason: got %q, want NoSignatures", res.Reason)
	}
}

func TestPolicyVerifier_AllowedAlgo_AcceptedKeyRefSurfaced(t *testing.T) {
	policy := TrustPolicy{
		AllowedAlgos:   []string{"sigstore-cosign-v1"},
		KeyRefPatterns: []string{"^cosign://gha-prod/.*$"},
	}
	signatures := []SignatureRef{
		sig("cosign://gha-prod/checkout-svc", "sigstore-cosign-v1", "bundle:1"),
	}
	res, err := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Trusted {
		t.Fatalf("expected trust: %+v", res)
	}
	if res.AcceptedKeyRef != "cosign://gha-prod/checkout-svc" {
		t.Errorf("AcceptedKeyRef wrong: %v", res.AcceptedKeyRef)
	}
	if res.Reason != "TrustedKeyRef" {
		t.Errorf("Reason wrong: %v", res.Reason)
	}
}

func TestPolicyVerifier_AlgoNotAllowed(t *testing.T) {
	policy := TrustPolicy{AllowedAlgos: []string{"sigstore-cosign-v1"}}
	signatures := []SignatureRef{
		sig("kms://arn:aws:kms:us-east-1:111111111111:key/abc", "ECDSA_SHA_256", "bundle:1"),
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if res.Trusted {
		t.Error("disallowed algo should not be trusted")
	}
	if res.Reason != "AlgoNotAllowed" {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestPolicyVerifier_KeyRefNotAllowed(t *testing.T) {
	policy := TrustPolicy{KeyRefPatterns: []string{"^cosign://prod/.*$"}}
	signatures := []SignatureRef{
		sig("cosign://staging/web", "sigstore-cosign-v1", "b"),
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if res.Trusted {
		t.Error("non-matching keyRef should not be trusted")
	}
	if res.Reason != "KeyRefNotAllowed" {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestPolicyVerifier_MalformedBundle(t *testing.T) {
	signatures := []SignatureRef{
		{}, // empty keyRef + algo + bundle
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, TrustPolicy{})
	if res.Trusted {
		t.Error("malformed bundle should not be trusted")
	}
	if res.Reason != "MalformedBundle" {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestPolicyVerifier_MultiSignature_AnyValidPasses(t *testing.T) {
	policy := TrustPolicy{KeyRefPatterns: []string{"^cosign://prod/.*$"}}
	signatures := []SignatureRef{
		sig("kms://wrong-key", "ECDSA_SHA_256", "b1"),
		sig("cosign://prod/web", "sigstore-cosign-v1", "b2"),
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if !res.Trusted {
		t.Fatalf("expected trust on second-good signature: %+v", res)
	}
	if res.AcceptedKeyRef != "cosign://prod/web" {
		t.Errorf("AcceptedKeyRef: %v", res.AcceptedKeyRef)
	}
}

// fakeCrypto is a stub Crypto implementation for testing the
// PolicyVerifier+Crypto delegation. Returns a fixed error for every
// non-allowed keyRef so the verifier's "structural pass + crypto fail"
// path is exercised.
type fakeCrypto struct {
	allowedKeyRef string
}

func (f fakeCrypto) Verify(_ context.Context, _ []byte, sig SignatureRef) error {
	if sig.KeyRef == f.allowedKeyRef {
		return nil
	}
	return errors.New("crypto: signature does not match")
}

func TestPolicyVerifier_CryptoFail_StructuralPassButCryptoRejects(t *testing.T) {
	policy := TrustPolicy{KeyRefPatterns: []string{"^cosign://prod/.*$"}}
	signatures := []SignatureRef{
		sig("cosign://prod/web", "sigstore-cosign-v1", "b1"),
	}
	v := PolicyVerifier{Crypto: fakeCrypto{allowedKeyRef: "cosign://prod/different"}}
	res, _ := v.Verify(context.Background(), nil, signatures, policy)
	if res.Trusted {
		t.Error("crypto-fail should not be trusted")
	}
	if res.Reason != "CryptoVerifyFailed" {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestPolicyVerifier_CryptoPass_BothLayersAccept(t *testing.T) {
	policy := TrustPolicy{KeyRefPatterns: []string{"^cosign://prod/.*$"}}
	signatures := []SignatureRef{
		sig("cosign://prod/web", "sigstore-cosign-v1", "b1"),
	}
	v := PolicyVerifier{Crypto: fakeCrypto{allowedKeyRef: "cosign://prod/web"}}
	res, _ := v.Verify(context.Background(), nil, signatures, policy)
	if !res.Trusted {
		t.Fatalf("expected trust: %+v", res)
	}
}

func TestPolicyVerifier_MalformedRegex_SurfacesAsReason(t *testing.T) {
	policy := TrustPolicy{KeyRefPatterns: []string{"["}}
	signatures := []SignatureRef{
		sig("cosign://prod/web", "sigstore-cosign-v1", "b"),
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if res.Trusted {
		t.Error("malformed regex should not produce trust")
	}
	if res.Reason != "MalformedPolicy" {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestPolicyVerifier_MultipleAllowedAlgos(t *testing.T) {
	policy := TrustPolicy{
		AllowedAlgos:   []string{"sigstore-cosign-v1", "ECDSA_SHA_256"},
		KeyRefPatterns: []string{".*"},
	}
	signatures := []SignatureRef{
		sig("kms://arn", "ECDSA_SHA_256", "b"),
	}
	res, _ := PolicyVerifier{}.Verify(context.Background(), nil, signatures, policy)
	if !res.Trusted {
		t.Errorf("ECDSA in allow-list should be trusted: %+v", res)
	}
}

func TestSummariseTrustPolicy(t *testing.T) {
	cases := []struct {
		policy TrustPolicy
		expect string
	}{
		{TrustPolicy{}, "unsigned=denied"},
		{TrustPolicy{UnsignedAllowed: true}, "unsigned=allowed"},
		{TrustPolicy{
			AllowedAlgos:    []string{"sigstore-cosign-v1"},
			KeyRefPatterns:  []string{"a", "b"},
			UnsignedAllowed: false,
		}, "algos=[sigstore-cosign-v1]"},
	}
	for _, tc := range cases {
		got := SummariseTrustPolicy(tc.policy)
		if !strings.Contains(got, tc.expect) {
			t.Errorf("SummariseTrustPolicy(%+v): got %q, want substring %q", tc.policy, got, tc.expect)
		}
	}
}

type okCrypto struct{}

func (okCrypto) Verify(_ context.Context, _ []byte, _ SignatureRef) error {
	return nil
}

func TestPolicyVerifier_EnforcesSignatures(t *testing.T) {
	if (PolicyVerifier{}).EnforcesSignatures() {
		t.Error("a structural-only verifier (Crypto nil) must not enforce signatures")
	}
	if !(PolicyVerifier{Crypto: okCrypto{}}).EnforcesSignatures() {
		t.Error("a verifier with a Crypto backend must enforce signatures")
	}
}
