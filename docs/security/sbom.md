# Software Bill of Materials

Crossbearing treats a **lean dependency tree as a product property**: buyers
security-review the SBOM, so a short, single-vendor tree is a feature, not a
convenience. Adding any dependency is a deliberate product decision.

- **Machine-readable:** [`sbom.cdx.json`](./sbom.cdx.json) — CycloneDX 1.6, generated
  from the shipped binary's build graph (only modules actually compiled in).
- **Regenerate:** [`scripts/sbom.sh`](../../scripts/sbom.sh).

## The whole tree, at a glance

| | |
|---|---|
| Third-party modules | **22** |
| Distinct upstream vendors | **1** (Amazon Web Services) |
| Source projects | `aws-sdk-go-v2` (and its service/internal modules) + `smithy-go` |
| Licenses | **Apache-2.0** (all 22) · the binary itself is FSL-1.1-ALv2 |
| Non-AWS dependencies | **0** |

There are no web frameworks, no ORMs, no third-party crypto (the engine uses the
Go standard library's `crypto/*`), no logging/serialization libraries beyond
stdlib, and **no telemetry, analytics, or networking SDKs of any kind**. Every
third-party line traces to the AWS SDK the engine needs to read your account.

## The five services

The product property is "`aws-sdk-go-v2` (5 services) + smithy + stdlib only."
The five service modules are `cloudtrail`, `iam`, `kms`, `s3`, `sts`; `config`
and `credentials` resolve credentials; the remaining modules are SDK internals
(endpoints, signing, event-stream, IMDS, SSO credential providers) pulled in
transitively by those. The full list with pinned versions is in the CycloneDX
file.

## Supply-chain posture

- **Reproducible + pinned.** Versions are pinned in `go.mod`/`go.sum` (with module
  checksums); the Go toolchain is pinned to `go1.26.4` in `go.mod`.
- **Vulnerability-scanned every build.** CI runs `govulncheck` as a hard-fail gate
  (`.github/workflows/ci.yml`) alongside `gofmt`, `go vet`, the race suite, and a
  fuzz smoke. The pin to `go1.26.4` was driven by govulncheck (GO-2026-5039 /
  GO-2026-5037); keep it patch-current.
- **Independently verifiable evidence.** The evidence package the engine emits is
  checked by a **separate, MIT-licensed, zero-dependency verifier**
  (`crossbearing/verify`) — so an auditor confirms the chain and signature
  without importing this engine or trusting its build.

## Regenerating this SBOM

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
./scripts/sbom.sh        # writes docs/security/sbom.cdx.json
```

The component list is platform-independent (the version pins are identical on
every OS/arch; the `goos`/`goarch` purl qualifiers reflect the host the SBOM was
generated on).
