# fab / Bedrock dress rehearsal

The demo that matches how the **nanohype agent platform** actually runs agents:
Claude agents on **AWS Bedrock** (the `fab` factory, `sdk-k8s` transport), doing
infra work through the **Bash tool** (`kubectl`, `aws`) and the **GitHub MCP
server**. It is the same pipeline the live EKS run will use — only the fixtures
get swapped for real exports.

```sh
./demo/fab/run.sh                 # the operator report (text)
./demo/fab/run.sh --format html > audit.html   # the Agent Attribution Audit (print → PDF)
```

No credentials needed — everything is offline captured samples in the real
schemas.

## The streams

| File | Stream | Side |
|---|---|---|
| `bedrock-invocations.jsonl` | Bedrock Model Invocation Logging (`toolUse`/`toolResult`) | **claim** |
| `k8s-audit.jsonl` | Kubernetes audit (`audit.k8s.io/v1`) | record |
| `aws-cloudtrail.json` | AWS CloudTrail | record |
| `github-audit.jsonl` | GitHub org audit log | record |

## What it shows

Two agent sessions; the join produces four of the five finding kinds:

- **Corroborated ×2** — `Bash(kubectl … scale …)` ⇄ the K8s `update:deployments/scale`
  record, and `mcp__github__merge_pull_request` ⇄ the `pull_request.merge` audit
  event (the MCP tool name normalizes to `mcp:github:…` to meet the seed map).
- **Unattributed** — an `s3:CreateBucket` on a production bucket by the agent's
  credential session, carrying no SourceIdentity → traces to no named human.
  *The headline.*
- **Mismatch** — the agent claimed `kubectl get configmaps`; the cluster recorded
  a `delete:configmaps`.
- **Unrecorded claim** — `aws dynamodb delete-table` the agent reported, with no
  corroborating record.

A plain **UnclaimedRecord** is intentionally absent: the unclaimed production
action (`s3:CreateBucket`) escalates to **Unattributed** because it's
production-touching — which is exactly the headline.

`expected-output.txt` is the committed golden (pinned by
`TestFabDemo_DeterministicOutput`; the html path by `TestFabDemo_HTML`);
regenerate it with `./demo/fab/run.sh` if a change to the output is intended.
The fixture timestamps must stay safely in the **past** — if they drift to near
or after the current date, the report window clamps to "now" and the golden
goes non-deterministic.

## When the live data lands

Swap the fixtures for real exports from the EKS run and re-run:
- the Bedrock invocation log (CloudWatch/S3 export) → `bedrock-invocations.jsonl`,
- the EKS audit log (`/aws/eks/<cluster>/cluster`) → `k8s-audit.jsonl`,
- CloudTrail (pulled live with a read-only role, or captured) → `aws-cloudtrail.json`.

The `--format html` output is the filled wedge deliverable, no hand-editing.
