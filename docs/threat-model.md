# Threat model

Crossbearing produces compliance evidence, so its own threat model is part
of the product: an auditor who asks "why should I trust this artifact?"
gets this document. Lens: STRIDE per trust boundary. Every mitigation
cites the code that implements it — claims here are checkable the same
way the product's findings are.

## Assets

1. **Evidence integrity** — a divergence report or Agent Evidence Package
   must be impossible to alter, reorder, truncate, or transplant without
   detection.
2. **The read-only promise** — the engine runs inside customer accounts on
   the strength of "it cannot mutate your infrastructure."
3. **Customer record confidentiality** — CloudTrail events can contain
   credential material (AssumeRole responses carry session tokens).
4. **Attribution honesty** — a binding must never claim more confidence
   than its evidence supports.

## Trust boundaries

```
 transcript .jsonl ──────(UNTRUSTED: agent-written)──────▶ ingest/claudecode
 Bedrock invocation log ─(UNTRUSTED: agent-written)──────▶ ingest/bedrock
 CloudTrail API ─────────(TLS + SigV4, AWS-auth'd)───────▶ ingest/cloudtrail
 audit-log files ────────(UNTRUSTED: operator-supplied)──▶ ingest/{cloudtrail,github,k8s,gcp,azure}
 app-humans .json ───────(UNTRUSTED: operator-supplied)──▶ GitHub attribution
 IAM GetRole ────────────(TLS + SigV4)───────────────────▶ attribute conventions
 KMS Sign ───────────────(TLS + SigV4)───────────────────▶ evidence signing
 local filesystem ◀──(0644 artifact, public-by-design)── pack output
```

## STRIDE

### Spoofing

- **A consumer trusts the signing key, not the emitting machine**: the
  package signature is detached over canonical bytes
  (`internal/pack/pack.go` `Payload`/`Sign`); the verifier is
  crossbearing/verify, a separate zero-dependency binary that checks the
  signature against a public-key file (`--public-key`) with no KMS call, so a
  package outlives its signing key (`internal/evidence/kms_signer.go`
  `KMSSigner`).
- **A declared operator is self-asserted and graded as such**:
  `corroborate.AttrDeclared` is documented as the weakest method; record
  -side bindings (SourceIdentity, session tags) outrank it and
  disagreements are surfaced verbatim, never resolved
  (`internal/attribute/bind.go` `resolve`).
- **An unsigned package cannot masquerade as signed**: `NoopSigner`
  output attaches nothing; `Sign` aborts on signer failure
  (`internal/pack/pack.go`).

### Tampering

- **Findings are hash-chained**; editing, removing, or reordering any
  finding breaks `VerifyChain` (`internal/pack/pack.go`), and the genesis
  hash is derived from the window + match policy so a chain cannot be
  transplanted between packages. Tamper cases are unit-tested
  (`internal/pack/pack_test.go`).
- **Inputs are digest-pinned**: every Claim/Record carries a sha256 over
  the raw bytes as ingested (`Provenance.Digest`), so post-join input
  substitution is detectable by re-fetching the locator.

### Repudiation

- **Findings are re-fetchable, never asserted** (the repo's hard rule):
  each carries a locator (`aws-cloudtrail:REGION/EVENT-ID`,
  `claude-code:PATH#UUID/TOOL-ID`) an auditor can independently resolve.
- The match policy travels inside the package (`PolicySnapshot`), so the
  join is reproducible with the same inputs.

### Information disclosure

- **Session tokens are never extracted**: the CloudTrail ingester reads
  identity fields only (`internal/ingest/cloudtrail/event.go` `rawEvent`);
  `responseElements.credentials` is not projected, logged, or packaged.
- **Packages carry digests, not raw events**; logs carry event IDs and
  counts, never payloads (`ingest.go` log sites).
- Access key IDs appear in session IDs deliberately — they identify
  credential sessions and are not secrets.
- The evidence package is written 0644 because it is an audit artifact
  designed to be handed to outsiders.

### Denial of service

- The whole run, every AWS call and retry included, runs under a context
  deadline set by `--timeout` (10 minutes by default; `0` disables it)
  (`cmd/crossbearing/main.go`); HTTP transport pools are bounded
  (`internal/aws/client.go`).
- LookupEvents pages at the API maximum (50) under SDK retry/backoff, and
  one window is capped at `Options.MaxPages` pages (default 5000, so 250,000
  events) in `internal/ingest/cloudtrail/ingest.go`. Exceeding the cap is an
  error, never a silent truncation, because a quietly capped window would
  understate what happened in the account.
- Untrusted-input parsers are fuzzed in CI (the `fuzz smoke` step in
  `.github/workflows/ci.yml`: `FuzzCLIRecordOps`, `FuzzParseARN`,
  `FuzzSplitJSONArrayOrLines`, and `FuzzIngest` for the k8s, gcp, azure,
  github and claudecode ingesters); a malformed transcript line or event degrades, never
  crashes (`extractedFromEnvelope` fallback, bad-line counters).

### Elevation of privilege

- **Read-only by architecture**: the engine calls
  `cloudtrail:LookupEvents`, `iam:GetRole`, and `kms:Sign` (only with
  `--kms-key`). Nothing in the production call graph mutates customer
  infrastructure.
- **Supply chain is a product property**: go.sum holds only aws-sdk-go-v2
  modules (the cloudtrail, iam, kms and sts clients, the signin, sso and
  ssooidc clients the credential chain pulls in, and SDK internals) plus
  smithy-go, and the rest of the binary is the standard library
  (`docs/security/sbom.cdx.json` lists the full set); `govulncheck` fails CI
  (`.github/workflows/ci.yml`); the toolchain is patch-pinned in go.mod.

Suggested engine role policy (least privilege):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*"},
    {"Effect": "Allow", "Action": "iam:GetRole", "Resource": "arn:aws:iam::ACCOUNT:role/*"},
    {"Effect": "Allow", "Action": "kms:Sign", "Resource": "arn:aws:kms:REGION:ACCOUNT:key/EVIDENCE-KEY-ID"}
  ]
}
```

The deployable, ready-to-`apply` version of this policy (Terraform + CloudFormation)
lives in [`deploy/readonly-role/`](../deploy/readonly-role/).

## Residual risks (accepted, documented)

1. **Same-credential actors are indistinguishable** without an enforced
   SourceIdentity: two terminals sharing an SSO cache share an access
   key. The product's answer is the convention checker that flags exactly
   this gap (`attribute.CheckTrustPolicy`) — it cannot be solved engine-side.
2. **CloudTrail lag (~15 min)**: a fresh window under-reports; the report
   prints a lag warning and re-runs are cheap.
3. **Claim-side deletion**: an agent (or operator) can delete a
   transcript before ingestion. Crossbearing detects the inverse
   (records without claims) but absence of a claim stream is visible only
   as ingestion silence — pair with retention policy on transcript storage.
4. **Operation-map conservatism**: the aws-CLI translator fails closed;
   commands it cannot parse make claims non-corroborable rather than
   wrongly corroborated. The cost is under-corroboration, not
   over-claiming.
