# Runbook

Operating `crossbearing report` and diagnosing the failures you will
actually hit. Build/usage basics are in the README; this is the
when-it-misbehaves document.

## The one command

```sh
AWS_PROFILE=<profile> crossbearing report \
  --transcript <session>.jsonl --region <region> \
  --operator <email> --principal <role-substring> \
  --pack evidence.json [--kms-key <arn>]
```

Exit 0 with a rendered report = success. Exit 1 prints
`crossbearing report: <error>` on stderr.

## Failure modes

| Symptom | Cause | Remedy |
| --- | --- | --- |
| `failed to load AWS config` / `failed to page cloudtrail events … ExpiredToken` | SSO session expired | `aws sso login --profile <profile>` and re-run |
| `failed to page cloudtrail events … AccessDenied` | engine role lacks `cloudtrail:LookupEvents` | grant the least-privilege policy in docs/threat-model.md |
| `could not fetch role for convention check` (warn, run continues) | missing `iam:GetRole` or role path issues | conventions section is skipped for that role only; findings are unaffected |
| `transcript yielded no sessions` | wrong file, or a transcript with no timestamped entries | confirm the path is a session `.jsonl` under `~/.claude/projects/<project>/` |
| report shows 0 records in a window that had activity | CloudTrail delivery lag (~15 min) or wrong `--region` | re-run after the lag; CloudTrail events land in the region of the API call |
| every record-corroborable claim is `unrecorded-claim` | record side ran in another region/account than the claims | match `--region`/profile to where the agent's calls actually landed |
| `skipped unparseable transcript lines` (warn) | concatenated/corrupt JSONL | count is logged; remaining lines ingest normally — investigate if the count is large |
| throttling on big windows | LookupEvents is limited to 2 req/s | SDK backoff usually absorbs it; shrink the window or `--pad` if it persists |
| `refusing to write a package that fails self-verification` | should never happen — chain built and verified in-process | file a bug with the run's stderr; nothing was written |
| `failed to sign evidence package` | KMS key wrong type/region or missing `kms:Sign` | key must be asymmetric SIGN_VERIFY (default algo ECDSA_SHA_256); omit `--kms-key` to emit explicitly-unsigned |

## Reading the report

- `corroborated n · mismatch n · unclaimed-record n · unrecorded-claim n ·
  unattributed n` — the tally auditors start from.
- `⇄` bindings are proven (corroborated findings share the credential
  session's access key); `≈` bindings only share the wall clock — treat
  them as leads, not conclusions.
- `gap:` lines under ATTRIBUTION name the trust-policy change that would
  make sessions attributable (usually: require `sts:SourceIdentity`).
- The lag note (`window ends <15m ago…`) means the window is not settled;
  re-run before treating absence-of-record as a divergence.

## Verifying an evidence package

The MIT verifier (github.com/crossbearing/verify — zero dependencies, no
engine code, fully offline) checks the hash chain and the detached
signature:

```sh
aws kms get-public-key --key-id <signature.keyRef> \
  --query PublicKey --output text > key.b64
verify evidence.json --public-key key.b64
```

Exit 0 = chain re-derives genesis→head AND the signature verifies.
Hand auditors the package, the public key, and that repo — they need
nothing else, including this codebase. The aep/1 format spec lives in
the verifier's README so verification is reimplementable from
documentation alone.

## Live validation

```sh
CROSSBEARING_LIVE=1 AWS_PROFILE=<profile> go test ./internal/ingest/cloudtrail -run TestLive -v
CROSSBEARING_TRANSCRIPT=<path>.jsonl go test ./internal/ingest/claudecode -run TestLive -v
```

Both are read-only. The cloudtrail one reports observed delivery lag and
sourceIdentity coverage for the account — useful before a demo.

## What the engine never does

No AWS mutations (see docs/threat-model.md), no telemetry, no network
calls besides the AWS APIs above. The only writes are the report to
stdout and the `--pack` file.
