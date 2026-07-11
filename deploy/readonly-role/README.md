# Crossbearing read-only audit role

The access crossbearing needs to run an attribution audit in your account —
nothing more. Pick your format, deploy, and hand back the role ARN + external id.

- **Terraform:** [`main.tf`](./main.tf) — `terraform apply -var crossbearing_principal_arn=… -var external_id=…`
- **CloudFormation:** [`cloudformation.yaml`](./cloudformation.yaml) — one stack, same parameters.

## What it grants — and nothing else

| Permission | Resource | Why |
|---|---|---|
| `cloudtrail:LookupEvents` | `*` (not scopable) | Read the management-event history the corroboration join runs against |
| `iam:GetRole` | roles in this account | Read a role's **trust policy** to check identity conventions (no credentials, no secrets) |
| `kms:Sign` *(optional)* | one named key ARN | Sign the Agent Evidence Package with **your** key — an engagement step; the free audit omits it |

These are the **only** AWS operations the `crossbearing report` binary invokes in
your account. Every one is read-only; **none can create, modify, or delete any
resource.** The role is read-only *by architecture*, not just by policy — see
[`../../docs/security/`](../../docs/security/).

## Trust model

- **Cross-account, named principal.** Only the crossbearing principal you're given
  can assume the role — no wildcard principals.
- **External id.** Every `AssumeRole` must present a shared secret you choose
  (≥ 16 chars), which you share with crossbearing out of band. This closes the
  [confused-deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
  gap that bare cross-account trust leaves open.
- **One-hour sessions**, and you revoke instantly by deleting the role.
- **Deploying twice?** Pass a distinct `role_name` (Terraform) / `RoleName` (CloudFormation)
  per deployment — the role and its inline policy both derive their names from it,
  so two stacks won't collide.

## What it does NOT grant

No `s3:*`, no `PutObject`, no write of any kind, no read of object data, no
secrets, no `kms:Decrypt`. The engine reads logs you already keep and writes the
evidence package to **your** storage under **your** key; no inbound access to
your data is required, and **no data leaves your account**.

## Verify the policy yourself

```sh
# Terraform: see the exact JSON before applying
terraform plan
# CloudFormation: lint + preview
aws cloudformation validate-template --template-body file://cloudformation.yaml
```

The granted actions are exactly the AWS calls the `crossbearing report` binary
invokes — `cloudtrail:LookupEvents` for the join, `iam:GetRole` for the trust-policy
convention check, and `kms:Sign` only when you pass `--kms-key`. There is no hidden
surface to grant for.
