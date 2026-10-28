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
| Third-party modules | **17** (`jq '.components \| length' docs/security/sbom.cdx.json`) |
| Distinct upstream vendors | **1** (Amazon Web Services) |
| Source projects | `aws-sdk-go-v2` (and its service/internal modules) + `smithy-go` |
| Licenses | **Apache-2.0** (every component; `scripts/sbom.sh` fails if a non-AWS module appears) · the binary itself is FSL-1.1-ALv2 |
| Non-AWS dependencies | **0** |

There are no web frameworks, no ORMs, no third-party crypto (the engine uses the
Go standard library's `crypto/*`), no logging/serialization libraries beyond
stdlib, and **no telemetry, analytics, or networking SDKs of any kind**. Every
third-party line traces to the AWS SDK the engine needs to read your account.

## The four services

The product property is "`aws-sdk-go-v2` (4 services) + smithy + stdlib only."
The four service modules the engine calls are `cloudtrail`, `iam`, `kms`, `sts`;
`config` and `credentials` resolve credentials, pulling in the `signin`, `sso` and
`ssooidc` credential-provider services; the remaining modules are SDK internals
(endpoints, config sources, SigV4a signing, accept-encoding, presigned URLs, IMDS)
pulled in transitively by those. The full list with pinned versions is in the CycloneDX
file.

## Supply-chain posture

- **Reproducible + pinned.** Versions are pinned in `go.mod`/`go.sum` (with module
  checksums); the Go toolchain is pinned by the `toolchain` directive in `go.mod`
  (`go mod edit -json | jq -r .Toolchain`).
- **Vulnerability-scanned every build.** CI runs `govulncheck` as a hard-fail gate
  (`.github/workflows/ci.yml`) alongside `gofmt`, `go vet`, the race suite, and a
  fuzz smoke. Stdlib advisories are most of what govulncheck reports against this
  tree, so the toolchain pin advances when the gate fails on one; CI also re-runs
  the gate weekly against an unchanged tree.
- **Independently verifiable evidence.** The evidence package the engine emits is
  checked by a **separate, MIT-licensed, zero-dependency verifier**
  (`crossbearing/verify`) — so an auditor confirms the chain and signature
  without importing this engine or trusting its build.

## Regenerating this SBOM

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@"$(grep -oE 'cyclonedx-gomod@v[0-9.]+' .github/workflows/ci.yml | cut -d@ -f2)"   # the version CI pins
./scripts/sbom.sh        # writes docs/security/sbom.cdx.json
```

The component list is platform-independent (the version pins are identical on
every OS/arch; the `goos`/`goarch` purl qualifiers reflect the host the SBOM was
generated on).
