# Vendor security questionnaire — answer pack

Pre-answered to the questions a CAIQ-Lite / SIG-Lite review asks. The throughline
is architectural: crossbearing runs **read-only inside your own AWS account**,
holds **no customer data**, and has **no backend or sub-processors** — so most
data-risk questions are answered by what the product *cannot* do, not by vendor
process maturity. Send this with the [SBOM](./sbom.md), the
[read-only role](../../deploy/readonly-role/), the
[data-flow](./data-flow.md), the [threat model](../threat-model.md), and the
[runbook](../runbook.md) as onboarding artifacts.

> Crossbearing is an early-stage vendor; answers are honest about that. Where an
> enterprise GRC program would point to a formal control, we point to the
> architecture that removes the risk the control mitigates.

## 1. Product & deployment

- **What is it?** A read-only evidence engine: it corroborates what your AI agents
  *claimed* they did against what your cloud *recorded*, and emits a signed,
  hash-chained Agent Evidence Package mapped to SOC 2 / ISO 42001 controls.
- **Deployment model?** A small Go binary run **inside your AWS account** (or on an
  operator's machine using a read-only role into it). There is **no SaaS, no
  multi-tenant platform, no vendor-hosted component** in the data path.
- **Where does it run?** Your account / your CI / your laptop. You control where.

## 2. Data — access, processing, storage, transmission

- **What customer data does it access?** CloudTrail management events and IAM role
  trust policies (read-only), plus any audit-log exports *you* hand it (K8s /
  Bedrock / GitHub / GCP / Azure). It reads logs you already keep.
- **Does customer data leave the account / reach the vendor?** **No.** The engine
  has no backend to send data to. The join runs locally; the evidence package is
  written to **your** storage. Crossbearing operates the binary but receives no
  customer data through it.
- **Does the vendor store customer data?** **No.** The engine is stateless between
  runs; it persists nothing except the evidence package it writes to your storage.
- **PII?** The engine processes identity strings that already exist in your logs
  (IAM ARNs, usernames, the human a session is attributed to). It does not collect,
  enrich, or transmit them anywhere; they remain in your account.
- **Data in transit?** Only between the binary and AWS service endpoints, over
  **TLS** (AWS SDK default). No other network egress.

## 3. Access management

- **How does the vendor access the account?** A single cross-account **read-only IAM
  role** you create ([`deploy/readonly-role`](../../deploy/readonly-role/)),
  assumable only by the named crossbearing principal **and** only when it presents
  an **external id** you choose (confused-deputy protection).
- **What can that access do?** `cloudtrail:LookupEvents` and `iam:GetRole` — and
  `kms:Sign` on one key you name, only if you opt into signing. **No write, create,
  delete, or object-read permission of any kind.**
- **Standing access?** No. Sessions are 1 hour; you revoke instantly by deleting the
  role. Access is read-only by architecture, not just by policy.
- **Least privilege?** The granted actions are exactly the AWS calls the `crossbearing
  report` binary invokes (`cloudtrail:LookupEvents`, `iam:GetRole`, and `kms:Sign` only
  when signing) — there is no broader surface to grant for.

## 4. Encryption

- **At rest?** The engine stores no data. The evidence package lives in **your** S3
  under **your** encryption; signing uses **your** KMS key.
- **In transit?** TLS to AWS endpoints.
- **Signing / integrity?** Findings are SHA-256 hash-chained; the package is signed
  detached with **your** AWS KMS key (ECDSA P-256 / `ECDSA_SHA_256` by default).
  Crossbearing never holds signing-key material — KMS performs the signature.
- **Key management?** Your KMS key, your key policy, your rotation. The engine calls
  only `kms:Sign`; it never exports, decrypts, or fetches key material.

## 5. Sub-processors & third parties

- **Sub-processors?** **None.** No SaaS dependencies, no hosting provider holding
  customer data (the engine runs in *your* account), no telemetry/analytics, no
  third-party APIs in the data path.
- **Third-party libraries?** The AWS SDK for Go v2 (5 services) + smithy-go — 22
  modules, all Apache-2.0, **zero non-AWS dependencies**. See [SBOM](./sbom.md).
- **AI/LLM use?** The engine **does not call any model** — it is read-only and
  consumes logs; it never sends your data to an LLM.

## 6. Secure development & vulnerability management

- **SDLC?** Every change is a reviewed, squash-merged pull request on a linear,
  SSH-signed (Verified) history; no direct pushes to `main`.
- **CI gates (all hard-fail):** `gofmt`, `go vet`, the test suite under `-race`, a
  fuzz smoke, and **`govulncheck`** — see `.github/workflows/ci.yml`.
- **Dependency hygiene?** Pinned `go.mod`/`go.sum` with checksums; toolchain pinned
  to `go1.26.4`; lean single-vendor tree (the SBOM is short by design).
- **Vulnerability response?** `govulncheck` gates every build; the toolchain pin is
  kept patch-current as it flags advisories.

## 7. Logging, monitoring & authentication

- **Authentication?** The engine has no auth system of its own — it uses **your**
  AWS IAM. It stores no credentials; it resolves them from the standard AWS chain
  at run time.
- **Audit of the vendor's own actions?** Every action the engine takes in your
  account is, by its nature, a read recorded in **your** CloudTrail — you can audit
  crossbearing with crossbearing.
- **Application logging?** Stdlib `slog`, to stderr; no log shipping anywhere.

## 8. Resilience, incident response & business continuity

- **Blast radius of a vendor compromise?** Minimal by construction: the engine holds
  no customer data and can only *read* (via a role you revoke at will), so a
  vendor-side incident exposes no customer data and cannot alter your infrastructure.
- **Availability dependency?** None on crossbearing — the engine is a binary you run;
  there is no service whose outage affects you. The emitted evidence remains
  verifiable offline by the independent MIT verifier even if crossbearing disappears.
- **Incident notification?** As an early-stage vendor we commit to prompt, direct
  notification of any issue affecting an engagement; the architecture means such an
  issue cannot involve loss of your data.

## 9. Compliance & assurance

- **Vendor certifications?** None yet (early-stage) — stated plainly. The
  compensating story is architectural (read-only, in-account, no data custody, no
  sub-processors) plus a published [threat model](../threat-model.md) and this pack.
- **What it produces for *your* compliance:** the Agent Evidence Package maps to
  SOC 2 CC6.1 / CC7.2 / CC8.1 and ISO/IEC 42001:2023 Annex A (A.3.2 / A.6.2.8 /
  A.6.2.6), and is independently verifiable — see the partner materials.
- **Threat model / pen test?** A code-cited STRIDE [threat model](../threat-model.md)
  is published with residual risks; a third-party review is welcomed as part of the
  design-partner engagement (the engagement *is* the security review).

---
*Questions this pack doesn't cover? They're usually answered the same way: the
engine is read-only, runs in your account, holds no data, and has no
sub-processors. Ask and we'll answer directly.*
