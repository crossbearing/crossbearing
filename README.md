# crossbearing

**What your AI agents did vs. what they said they did.**

> A cross bearing is how a navigator fixes their true position from independent
> reference lines. crossbearing is how you verify what your AI agents actually
> did.

crossbearing is a read-only evidence engine, deployed in your own AWS account,
that corroborates AI-agent activity against the records your infrastructure
already keeps — CloudTrail, GitHub audit logs, Kubernetes audit logs, CI runner
logs — and packages the result as auditor-ready, tamper-evident evidence
anchored to your own KMS key.

Nothing installs in the agent path. One read-only IAM role connects it.

![A crossbearing divergence report: every finding kind in one run, headlined by an unattributed production action](https://crossbearing.dev/demo/crossbearing-aws-demo-poster.png)
_See it live at [crossbearing.dev](https://crossbearing.dev)._

## What it produces

1. **Attribution** — every agent session bound to a named human identity, via
   verifiable conventions (STS SourceIdentity + session tags, GitHub app
   installation mapping, Kubernetes impersonation headers) that crossbearing
   continuously checks are actually enforced.
2. **The divergence report** — agent-claimed actions joined against
   cloud-recorded reality: what diverged, and which production-touching actions
   belong to no named human at all.
3. **The Agent Evidence Package** — a versioned, tamper-evident artifact
   (hash-chained, signed with *your* KMS key) mapped to SOC 2 CC-series
   controls (ISO 42001 Annex A available), verifiable by an open CLI with or
   without us.

## Demo

See the divergence report in five seconds, fully offline, no credentials:

```sh
./demo/run.sh
```

3 agent claims corroborated across CloudTrail + Kubernetes + GitHub, and 1
unattributed production action the agent never reported. See
[`demo/README.md`](demo/README.md) for the story.

For more named divergence scenarios, each running detection through fix
fully offline, see the
[scenario gallery](https://github.com/crossbearing/scenarios).

## Usage

Install the CLI:

```sh
go install github.com/crossbearing/crossbearing/cmd/crossbearing@latest
```

Build and test (Go ≥ 1.26):

```sh
go build ./...
go test ./... -count=1 -race
```

Run a divergence report for one Claude Code session against CloudTrail.
Credentials come from the standard AWS chain (`AWS_PROFILE`, IRSA, env vars);
every AWS call the engine makes is read-only (`cloudtrail:LookupEvents`,
`iam:GetRole`, and `kms:Sign` only when `--kms-key` is set):

```sh
AWS_PROFILE=<profile> crossbearing report \
  --transcript ~/.claude/projects/<project>/<session-id>.jsonl \
  --region us-west-2 \
  --operator you@example.com \
  --principal <role-or-session-substring> \
  --pack evidence.json
```

| Flag | Meaning |
| --- | --- |
| `--transcript` | Claude Code session transcript (`.jsonl`) — required |
| `--region` | AWS region to read CloudTrail in (or `AWS_REGION`) — required |
| `--operator` | declared human operator; self-reported, graded as the weakest binding until records corroborate it |
| `--principal` | substring filter: only join records whose acting principal matches (the credentials the agent wielded) |
| `--pad` | how far beyond the session window to ingest records (default `30m`) |
| `--tag-keys` | session-tag keys that may carry a human binding (default `operator,human,owner`) |
| `--pack` | write the Agent Evidence Package (JSON) to this path |
| `--kms-key` | KMS signing key ARN; omitted = the package is *explicitly* unsigned |
| `--github-audit` / `--github-org` | join a GitHub org audit log (API JSON or JSONL export) as a second record stream |
| `--github-app-humans` | JSON file mapping bot/App actor logins to their accountable humans — mapped bots carry their human as per-event identity, like STS SourceIdentity |
| `--k8s-audit` / `--k8s-cluster` | join a Kubernetes audit log (JSONL or EventList) as a third record stream |
| `--gcp-audit` / `--gcp-project` | join a GCP Cloud Audit Log (gcloud JSON array or JSONL) as a fourth record stream |
| `--azure-audit` / `--azure-subscription` | join an Azure Activity Log (az monitor activity-log list -o json) as a fifth record stream |
| `--aws-cloudtrail` | captured CloudTrail events (JSON array) instead of the live API — runs fully offline, no AWS creds |
| `--production-match` | substring marking a target as production-touching; an unclaimed production action with no human binding escalates to Unattributed |

The report prints corroborated/diverged findings with re-fetchable provenance,
the agent-session ⇄ credential-session bindings (corroborated vs
window-overlap confidence), and trust-policy convention gaps for every role
the joined records acted as. CloudTrail delivers with up to ~15 minutes of
lag — a window ending near now is not settled.

### Live validation tests

The suites are hermetic by default. Two env-gated tests validate against real
infrastructure:

```sh
# CloudTrail ingestion against a real account (read-only)
CROSSBEARING_LIVE=1 AWS_PROFILE=<profile> \
  go test ./internal/ingest/cloudtrail -run TestLive -v

# transcript ingestion against a real Claude Code session file
CROSSBEARING_TRANSCRIPT=<path>.jsonl \
  go test ./internal/ingest/claudecode -run TestLive -v
```

## Architecture

```
internal/
├── aws/           lean AWS client layer (CloudTrail, S3, KMS, IAM, STS)
├── evidence/      KMS signing + verification (ECDSA, detached signatures)
├── ingest/        stream ingesters → corroborate vocabulary
│   ├── cloudtrail/   record side: LookupEvents → Records + credential sessions
│   ├── claudecode/   claim side: transcripts → Claims + declared sessions
│   ├── github/       record side: org audit log → Records + actor sessions
│   ├── k8s/          record side: audit events → Records + impersonation sessions
│   ├── gcp/          record side: Cloud Audit Logs → Records + delegation sessions
│   └── azure/        record side: Activity Log → Records + delegation sessions
├── attribute/     session ⇄ session binding + trust-policy convention checks
├── corroborate/   the divergence join: claims vs records (the core)
└── pack/          Agent Evidence Package builder (aep/1: hash chain + signature + SOC2 map)
cmd/
└── crossbearing/  the engine binary (`report`, `version`)
```

Dependencies are a product property: `aws-sdk-go-v2` (five services) +
`smithy` + the Go standard library, nothing else. Buyers security-review the
SBOM; every addition is a product decision.

## License

[FSL-1.1-ALv2](LICENSE.md) — source-available; converts to Apache 2.0 two
years after each release. The evidence **verifier CLI** lives in a separate,
MIT-licensed repository so evidence remains verifiable independently of this
codebase and its license.
