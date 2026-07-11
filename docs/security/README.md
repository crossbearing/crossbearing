# Crossbearing security review pack

Everything a buyer's security team needs to clear crossbearing — assembled so the
review is an **onboarding step, not a deal gate**. The whole pack rests on one
architectural fact: crossbearing is **read-only, runs inside your own account,
holds no customer data, and has no backend or sub-processors.**

| Artifact | What it answers |
|---|---|
| [`questionnaire.md`](./questionnaire.md) | The CAIQ-Lite / SIG-Lite questions, pre-answered |
| [`data-flow.md`](./data-flow.md) | What touches what, and which boundaries data crosses (none, to us) |
| [`sbom.md`](./sbom.md) + [`sbom.cdx.json`](./sbom.cdx.json) | The full dependency tree — 22 modules, one vendor, all Apache-2.0 |
| [`../../deploy/readonly-role/`](../../deploy/readonly-role/) | The exact, minimal IAM role (Terraform + CloudFormation) |
| [`../threat-model.md`](../threat-model.md) | STRIDE per boundary, code-cited, with residual risks |
| [`../runbook.md`](../runbook.md) | Operations, failure modes, and how to verify a package |

## The short version, for the security reviewer

- **Read-only by architecture.** The binary can only read (CloudTrail, IAM trust
  policies) and sign with a key you name. It cannot create, modify, or delete
  anything. The granted IAM actions match the engine's actual AWS calls line for line.
- **No data leaves your account.** No vendor backend, no SaaS, no telemetry. The
  join runs locally; the evidence package is written to your storage under your key.
- **No sub-processors.** Zero third-party services in the data path; the only
  third-party code is the AWS SDK (Apache-2.0), scanned by `govulncheck` every build.
- **Independently verifiable.** A separate MIT-licensed, zero-dependency verifier
  checks the evidence offline — so the proof survives even if crossbearing does not.
- **Auditable with itself.** Every action the engine takes is a read in your own
  CloudTrail.

Send the pack, point at the role, and the review answers itself. Anything not
covered here, ask — the answer is almost always "read-only, in your account, no
data held."
