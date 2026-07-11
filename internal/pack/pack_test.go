package pack

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/attribute"
	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/evidence"
)

var (
	t0  = time.Date(2026, 6, 10, 3, 0, 0, 0, time.UTC)
	gen = time.Date(2026, 6, 10, 6, 0, 0, 0, time.UTC)
)

func testInput() Input {
	rec := corroborate.Record{
		ID: "evt-1", Source: corroborate.SourceCloudTrail,
		Operation: "sts:GetCallerIdentity", RecordedAt: t0,
		Raw: corroborate.Provenance{Locator: "aws-cloudtrail:us-west-2/evt-1", Digest: "abc"},
	}
	prodRec := corroborate.Record{
		ID: "evt-2", Source: corroborate.SourceCloudTrail,
		Operation: "s3:CreateBucket", RecordedAt: t0.Add(time.Minute),
		ProductionTouching: true,
		Raw:                corroborate.Provenance{Locator: "aws-cloudtrail:us-west-2/evt-2", Digest: "def"},
	}
	claim := corroborate.Claim{
		ID: "toolu_1", SessionID: "s1",
		Operation: "Bash(aws sts get-caller-identity)", ClaimedAt: t0,
		Raw: corroborate.Provenance{Locator: "claude-code:/t.jsonl#u1/toolu_1", Digest: "ghi"},
	}
	return Input{
		Report: &corroborate.Report{
			From: t0.Add(-time.Hour), To: t0.Add(time.Hour),
			Sessions: []corroborate.Session{{ID: "s1", Agent: "claude-code", StartedAt: t0.Add(-30 * time.Minute), EndedAt: t0.Add(30 * time.Minute)}},
			Findings: []corroborate.Finding{
				{Kind: corroborate.Corroborated, SessionID: "s1", Claim: &claim, Record: &rec, Why: "corroborated"},
				{Kind: corroborate.UnclaimedRecord, SessionID: "s1", Record: &prodRec, Why: "unclaimed"},
				{Kind: corroborate.Unattributed, SessionID: "s1", Record: &prodRec, Why: "unattributed"},
			},
		},
		Policy:      corroborate.MatchPolicy{Window: 20 * time.Minute, OperationMap: map[string][]string{"Bash(aws sts get-caller-identity)": {"sts:GetCallerIdentity"}}},
		Conventions: []attribute.RoleConventions{{RoleARN: "arn:aws:iam::1:role/sso-admin"}}, // no SourceIdentity req → gap
		Region:      "us-west-2",
		GeneratedAt: gen,
	}
}

func TestBuild_ChainAndVerify(t *testing.T) {
	t.Parallel()
	p, err := Build(testInput())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if p.Version != Version {
		t.Errorf("Version = %q, want %q", p.Version, Version)
	}
	if p.Chain.Length != 3 || len(p.Findings) != 3 {
		t.Fatalf("chain length = %d, findings = %d, want 3", p.Chain.Length, len(p.Findings))
	}
	if p.Findings[0].Prev != p.Chain.Genesis {
		t.Error("first link's prev is not the genesis hash")
	}
	if p.Findings[2].Link != p.Chain.Head {
		t.Error("last link is not the chain head")
	}
	if err := VerifyChain(p); err != nil {
		t.Fatalf("VerifyChain() on a fresh package: %v", err)
	}
}

func TestBuild_Deterministic(t *testing.T) {
	t.Parallel()
	a, err := Build(testInput())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(testInput())
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := a.Payload()
	pb, _ := b.Payload()
	if string(pa) != string(pb) {
		t.Fatal("identical inputs produced different payloads; canonical form is not deterministic")
	}
}

func TestVerifyChain_DetectsTamper(t *testing.T) {
	t.Parallel()

	t.Run("edited finding", func(t *testing.T) {
		t.Parallel()
		p, _ := Build(testInput())
		p.Findings[1].Finding.Why = "totally fine, nothing to see"
		if err := VerifyChain(p); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("VerifyChain() = %v, want digest mismatch", err)
		}
	})

	t.Run("removed finding", func(t *testing.T) {
		t.Parallel()
		p, _ := Build(testInput())
		p.Findings = append(p.Findings[:1], p.Findings[2:]...)
		if err := VerifyChain(p); err == nil {
			t.Fatal("VerifyChain() accepted a truncated chain")
		}
	})

	t.Run("reordered findings", func(t *testing.T) {
		t.Parallel()
		p, _ := Build(testInput())
		p.Findings[0], p.Findings[1] = p.Findings[1], p.Findings[0]
		if err := VerifyChain(p); err == nil {
			t.Fatal("VerifyChain() accepted a reordered chain")
		}
	})

	t.Run("transplanted window", func(t *testing.T) {
		t.Parallel()
		p, _ := Build(testInput())
		p.Window.From = p.Window.From.Add(time.Hour)
		if err := VerifyChain(p); err == nil || !strings.Contains(err.Error(), "genesis") {
			t.Fatalf("VerifyChain() = %v, want genesis mismatch (chain bound to window)", err)
		}
	})
}

func TestControls_Mapping(t *testing.T) {
	t.Parallel()
	p, _ := Build(testInput())
	byControl := map[string]ControlMapping{}
	for _, c := range p.Controls {
		byControl[c.Control] = c
	}
	if len(p.Controls) != 6 {
		t.Fatalf("controls = %d, want 3 SOC 2 + 3 ISO 42001, all shipped populated-or-not", len(p.Controls))
	}
	if got := byControl["CC6.1"].FindingIndexes; len(got) != 1 || got[0] != 2 {
		t.Errorf("CC6.1 findings = %v, want the unattributed finding [2]", got)
	}
	if got := byControl["CC6.1"].ConventionRoles; len(got) != 1 {
		t.Errorf("CC6.1 convention roles = %v, want the anonymous-by-default role", got)
	}
	if got := byControl["CC7.2"].FindingIndexes; len(got) != 2 {
		t.Errorf("CC7.2 findings = %v, want corroborated + unclaimed", got)
	}
	if got := byControl["CC8.1"].FindingIndexes; len(got) != 1 || got[0] != 1 {
		t.Errorf("CC8.1 findings = %v, want the production-touching unclaimed record [1]", got)
	}

	// ISO/IEC 42001 maps the SAME findings to the analogous Annex A controls.
	if fw := byControl["A.3.2"].Framework; fw != "ISO/IEC 42001:2023" {
		t.Errorf("A.3.2 framework = %q, want ISO/IEC 42001:2023", fw)
	}
	if got := byControl["A.3.2"].FindingIndexes; len(got) != 1 || got[0] != 2 {
		t.Errorf("A.3.2 (AI roles & responsibilities) findings = %v, want the unattributed finding [2]", got)
	}
	if got := byControl["A.6.2.8"].FindingIndexes; len(got) != 2 {
		t.Errorf("A.6.2.8 (event logging) findings = %v, want corroborated + unclaimed", got)
	}
	if got := byControl["A.6.2.6"].FindingIndexes; len(got) != 1 || got[0] != 1 {
		t.Errorf("A.6.2.6 (operation & monitoring) findings = %v, want the production-touching unclaimed record [1]", got)
	}
	// The SOC 2 framework label is set on the originals too.
	if fw := byControl["CC6.1"].Framework; fw != "SOC 2 (TSC)" {
		t.Errorf("CC6.1 framework = %q, want SOC 2 (TSC)", fw)
	}
}

// captureSigner records what it signed and returns a fixed bundle.
type captureSigner struct {
	signed []byte
	err    error
}

func (s *captureSigner) Sign(_ context.Context, payload []byte) (evidence.SignatureBundle, error) {
	if s.err != nil {
		return evidence.SignatureBundle{}, s.err
	}
	s.signed = payload
	return evidence.SignatureBundle{Signature: []byte("sig"), KeyRef: "arn:aws:kms:us-west-2:1:key/k", Algo: "ECDSA_SHA_256"}, nil
}

func TestSign_CoversPayloadWithoutSignature(t *testing.T) {
	t.Parallel()
	p, _ := Build(testInput())
	want, _ := p.Payload()

	s := &captureSigner{}
	if err := p.Sign(context.Background(), s); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if p.Signature == nil || p.Signature.KeyRef == "" {
		t.Fatal("signature not attached")
	}
	if string(s.signed) != string(want) {
		t.Fatal("signature covers different bytes than Payload()")
	}
	// Attaching the signature must not change what a verifier re-derives.
	after, _ := p.Payload()
	if string(after) != string(want) {
		t.Fatal("Payload() changed after attaching the signature")
	}
}

func TestSign_NoopStaysUnsigned(t *testing.T) {
	t.Parallel()
	p, _ := Build(testInput())
	if err := p.Sign(context.Background(), evidence.NoopSigner{}); err != nil {
		t.Fatalf("Sign(noop) error = %v", err)
	}
	if p.Signature != nil {
		t.Fatal("NoopSigner must leave the package explicitly unsigned, not pseudo-signed")
	}
}

func TestSign_FailureAborts(t *testing.T) {
	t.Parallel()
	p, _ := Build(testInput())
	if err := p.Sign(context.Background(), &captureSigner{err: errors.New("kms down")}); err == nil {
		t.Fatal("Sign() swallowed a signer failure")
	}
	if p.Signature != nil {
		t.Fatal("failed signing attached a signature")
	}
}

func TestBuild_EmptyReport(t *testing.T) {
	t.Parallel()
	p, err := Build(Input{Report: &corroborate.Report{}, GeneratedAt: gen})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if p.Chain.Length != 0 || p.Chain.Head != p.Chain.Genesis {
		t.Errorf("empty chain: head %s should equal genesis %s", p.Chain.Head, p.Chain.Genesis)
	}
	if err := VerifyChain(p); err != nil {
		t.Fatalf("VerifyChain(empty) = %v", err)
	}
}
