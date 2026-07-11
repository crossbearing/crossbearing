// Package pack builds the Agent Evidence Package: the signed, hash-chained
// artifact that turns a divergence report into something an auditor can
// hold. Three properties make it evidence rather than output:
//
//   - every finding inside carries Provenance (the hard rule) — each one
//     is re-fetchable from the streams it came from;
//   - the findings are hash-chained, so removing, reordering, or editing
//     any one of them breaks the chain visibly;
//   - the whole package is signed detached (KMS in production), so the
//     consumer trusts the key, not the machine that emitted the file.
//
// Verification is deliberately implementable from this file alone: the
// separate MIT-licensed verifier CLI (crossbearing/verify) re-derives the
// chain and checks the signature without importing this engine.
package pack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/crossbearing/crossbearing/internal/attribute"
	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/evidence"
)

// Version identifies the package format; verifiers reject versions they
// don't know rather than guessing.
const Version = "aep/1"

// Package is the Agent Evidence Package document. Serialized as JSON; the
// canonical form (for chaining and signing) is this struct's
// encoding/json serialization with Signature omitted.
type Package struct {
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`

	// Window is what the package covers, echoing the report.
	Window Window `json:"window"`

	// Policy snapshots the match policy the join ran under — every
	// parameter an auditor may ask about travels inside the evidence.
	Policy PolicySnapshot `json:"policy"`

	Sessions    []corroborate.Session       `json:"sessions"`
	Bindings    []attribute.Binding         `json:"bindings,omitempty"`
	Conventions []attribute.RoleConventions `json:"conventions,omitempty"`
	Findings    []ChainedFinding            `json:"findings"`
	Chain       ChainHead                   `json:"chain"`
	Controls    []ControlMapping            `json:"controls"`
	Signature   *evidence.SignatureBundle   `json:"signature,omitempty"`
}

// Window bounds the evidence in time and place.
type Window struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Region string    `json:"region,omitempty"`
}

// PolicySnapshot is the auditor-readable form of corroborate.MatchPolicy.
type PolicySnapshot struct {
	Window       string              `json:"window"`
	OperationMap map[string][]string `json:"operationMap,omitempty"`
}

// ChainedFinding is one link: the finding, its own digest, and the link
// hash binding it to everything before it.
type ChainedFinding struct {
	Index   int                 `json:"index"`
	Finding corroborate.Finding `json:"finding"`
	// Digest is sha256(canonical JSON of the finding).
	Digest string `json:"digest"`
	// Prev is the previous link hash (the genesis hash for index 0).
	Prev string `json:"prev"`
	// Link is sha256(hex(Prev) || hex(Digest)) — the chain step.
	Link string `json:"link"`
}

// ChainHead summarizes the chain for quick integrity statements.
type ChainHead struct {
	Algo string `json:"algo"` // "sha256-hex-concat"
	// Genesis anchors the chain to the window and policy, so a chain
	// cannot be transplanted between packages.
	Genesis string `json:"genesis"`
	Head    string `json:"head"`
	Length  int    `json:"length"`
}

// Input is everything Build needs. GeneratedAt is injected, not sampled,
// so identical inputs produce byte-identical packages.
type Input struct {
	Report      *corroborate.Report
	Policy      corroborate.MatchPolicy
	Bindings    []attribute.Binding
	Conventions []attribute.RoleConventions
	Region      string
	GeneratedAt time.Time
}

// Build assembles an unsigned package: chains the findings in report
// order and maps them onto SOC 2 CC and ISO/IEC 42001 Annex A controls.
func Build(in Input) (*Package, error) {
	if in.Report == nil {
		return nil, fmt.Errorf("report is required")
	}

	p := &Package{
		Version: Version,
		// Times normalize to UTC: canonical bytes must not depend on the
		// timezone of the machine that emitted the package.
		GeneratedAt: in.GeneratedAt.UTC(),
		Window:      Window{From: in.Report.From.UTC(), To: in.Report.To.UTC(), Region: in.Region},
		Policy: PolicySnapshot{
			Window:       in.Policy.Window.String(),
			OperationMap: in.Policy.OperationMap,
		},
		Sessions:    in.Report.Sessions,
		Bindings:    in.Bindings,
		Conventions: in.Conventions,
	}

	genesis, err := genesisHash(p.Window, p.Policy)
	if err != nil {
		return nil, err
	}
	prev := genesis
	for i, f := range in.Report.Findings {
		digest, err := canonicalDigest(f)
		if err != nil {
			return nil, fmt.Errorf("failed to digest finding %d: %w", i, err)
		}
		link := chainStep(prev, digest)
		p.Findings = append(p.Findings, ChainedFinding{
			Index: i, Finding: f, Digest: digest, Prev: prev, Link: link,
		})
		prev = link
	}
	p.Chain = ChainHead{Algo: "sha256-hex-concat", Genesis: genesis, Head: prev, Length: len(p.Findings)}
	p.Controls = mapControls(p.Findings, p.Conventions)
	return p, nil
}

// Payload returns the canonical bytes a signature covers: the package
// serialized with Signature omitted.
func (p *Package) Payload() ([]byte, error) {
	clone := *p
	clone.Signature = nil
	b, err := json.Marshal(&clone)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize package payload: %w", err)
	}
	return b, nil
}

// Sign attaches a detached signature over Payload(). Signing failures
// abort: an unsigned-but-claimed-signed package must never exist.
func (p *Package) Sign(ctx context.Context, signer evidence.Signer) error {
	payload, err := p.Payload()
	if err != nil {
		return err
	}
	bundle, err := signer.Sign(ctx, payload)
	if err != nil {
		return fmt.Errorf("failed to sign evidence package: %w", err)
	}
	if bundle.KeyRef == "" && bundle.Signature == nil {
		return nil // NoopSigner: an explicitly unsigned package stays unsigned
	}
	p.Signature = &bundle
	return nil
}

// VerifyChain re-derives the hash chain and reports the first
// inconsistency. This is the integrity half of what crossbearing/verify
// does; it lives here so the engine's own tests hold the format honest.
func VerifyChain(p *Package) error {
	genesis, err := genesisHash(p.Window, p.Policy)
	if err != nil {
		return err
	}
	if p.Chain.Genesis != genesis {
		return fmt.Errorf("chain genesis mismatch: package says %s, window+policy derive %s", p.Chain.Genesis, genesis)
	}
	prev := genesis
	for i, cf := range p.Findings {
		digest, err := canonicalDigest(cf.Finding)
		if err != nil {
			return err
		}
		if cf.Digest != digest {
			return fmt.Errorf("finding %d: digest mismatch (content edited)", i)
		}
		if cf.Prev != prev {
			return fmt.Errorf("finding %d: prev-link mismatch (chain reordered or truncated)", i)
		}
		if want := chainStep(prev, digest); cf.Link != want {
			return fmt.Errorf("finding %d: link mismatch", i)
		}
		prev = cf.Link
	}
	if p.Chain.Head != prev {
		return fmt.Errorf("chain head mismatch: package says %s, findings derive %s", p.Chain.Head, prev)
	}
	if p.Chain.Length != len(p.Findings) {
		return fmt.Errorf("chain length %d != findings %d", p.Chain.Length, len(p.Findings))
	}
	return nil
}

func genesisHash(w Window, pol PolicySnapshot) (string, error) {
	b, err := json.Marshal(struct {
		Window Window         `json:"window"`
		Policy PolicySnapshot `json:"policy"`
	}{w, pol})
	if err != nil {
		return "", fmt.Errorf("failed to derive genesis: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func chainStep(prevHex, digestHex string) string {
	sum := sha256.Sum256([]byte(prevHex + digestHex))
	return hex.EncodeToString(sum[:])
}
