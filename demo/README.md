# crossbearing demo

The divergence report in one command, fully offline — no AWS / GCP / Azure
credentials, no network:

```sh
./demo/run.sh
```

It prints the report in `expected-output.txt` in about five seconds.

## The story it tells

An AI agent ran a deploy session (`demo/transcript.jsonl`). It **claimed**
three actions:

1. `aws sts get-caller-identity`
2. `kubectl create deployment api -n prod`
3. `git push origin main`

crossbearing joins those claims against what three independent clouds
actually **recorded** — captured CloudTrail, a Kubernetes audit log, and a
GitHub org audit log — and reports the divergence:

```
unattributed 1 · mismatch 0 · unclaimed-record 0 · unrecorded-claim 0 · corroborated 3
```

- **3 corroborated** — each claim matched its record, across three
  different control planes. The agent told the truth about these.
- **1 unattributed** — CloudTrail also recorded an `s3:CreateBucket` on a
  **production** bucket (`prod-customer-exports`) that the agent **never
  claimed**, inside its session window. And because the deploy role carries
  no STS `SourceIdentity`, that production change is bound to **no named
  human**. That is the finding the product exists to surface: a
  production-touching action an AI agent took, didn't report, and that no
  person is accountable for.

Every finding carries re-fetchable provenance (the locator + a SHA-256
digest of the raw event), so it is evidence an auditor can independently
verify — not an assertion.

## The data is real-shaped

The sample audit logs are not invented formats: each is in the exact
schema the engine was **live-validated** against —
`aws cloudtrail lookup-events`, `audit.k8s.io/v1` events, and a GitHub
org audit-log export. Only the identifiers (account, role, bucket, org)
are demo values.

## Running it on your own data

Drop the `--aws-cloudtrail` and pass `--region` to read live CloudTrail
from your own account, and point the stream flags at your own exports:

```sh
crossbearing report \
  --transcript ~/.claude/projects/<project>/<session>.jsonl \
  --region us-east-1 \
  --k8s-audit cluster-audit.jsonl --k8s-cluster prod \
  --gcp-audit gcp.json --gcp-project my-proj \
  --azure-audit azure.json --azure-subscription my-sub \
  --production-match prod- \
  --pack evidence.json --kms-key <arn>
```

See the repo README for every flag and `docs/runbook.md` for verifying the
signed evidence package.
