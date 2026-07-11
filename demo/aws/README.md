# AWS demo — the main bearing, every case in one run

The pure-AWS/CloudTrail demo: one agent session, one offline `crossbearing
report`, and **every finding kind on screen at once**. It's the scenario the
crossbearing.dev demo (both the screencast and the in-browser run) loads by
default, and the golden test (`TestAWSDemo_DeterministicOutput`) keeps the two
from drifting.

No AWS credentials, no real account, no secrets — the transcript and CloudTrail
capture are synthetic samples in the real schemas the engine validated against
live. Identifiers are AWS-docs placeholders (`111122223333`, `prod-payments-*`,
`ASIA…0001`).

## The story it tells

An agent (`agent-deployer/deploy-bot`) runs a short AWS maintenance session. Its
transcript claims a few read-only calls. CloudTrail tells the fuller story:

| What the agent claimed | What CloudTrail recorded | Finding |
|---|---|---|
| `aws sts get-caller-identity` | `sts:GetCallerIdentity` | **corroborated** |
| `aws ec2 describe-instances` | `ec2:DescribeInstances` | **corroborated** |
| `aws s3api get-bucket-policy` (read) | `s3:PutBucketPolicy` (write) | **mismatch** |
| `aws rds describe-db-instances` | *(nothing)* | **unrecorded-claim** |
| *(nothing)* | `s3:CreateBucket` on a prod bucket | **unattributed** → **agent-suspect** |
| *(nothing)* | `iam:ListAccessKeys` | **unclaimed-record** |

The **how-it-happens** is in the ATTRIBUTION line: the credential session is
*proven* to be the agent's (corroborated), yet it binds to **no human** — the
role carries no enforced SourceIdentity. The **how-we-help** is the AGENT-SUSPECT
tier: the orphaned production bucket is pinned to the agent's own proven
credential, and every finding carries a re-fetchable locator + SHA-256.

## Run it

```sh
./demo/aws/run.sh            # the text report
```
