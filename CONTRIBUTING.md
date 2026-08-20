# Contributing

crossbearing is a read-only evidence engine. It runs in someone else's AWS
account and produces artifacts an auditor may be asked to rely on. That shapes
every rule below — most of them exist because the output has to survive being
doubted, not because they are tidy.

Read `CLAUDE.md` for the architecture and the reasoning behind each package.
This file is the short version of what a change has to clear.

## Ground rules

**Read-only by architecture.** Nothing in this engine mutates customer
infrastructure. The AWS surface is `cloudtrail:LookupEvents`, `iam:GetRole`,
and `kms:Sign` — the last only when `--kms-key` is passed. A change that adds a
write capability is not a code review question, it is a product decision.

**Dependencies are a product property.** `go.sum` is `aws-sdk-go-v2` (four
services: cloudtrail, iam, kms, sts) plus `smithy` plus the standard library.
Nothing else, and no testify — tests use stdlib `testing`. Buyers security-review
the SBOM, and a dependency carrying only dead code is a question that review will
ask. Adding one is a product decision, not a convenience. There are zero
`k8s.io`, `sigs.k8s.io`, or `rackctl` imports, and that is permanent.

**Every Finding carries Provenance.** A locator it can be re-fetched at, and a
digest over the bytes as ingested. Findings are re-checkable, never asserted.
Explainable-to-an-auditor beats clever.

**Never write an invariant you have not tested.** This is the one that bites.
A safety invariant that is merely reasoned about tends to be false in a case an
adversarial re-check finds in a line or two — and it is described as impossible
in the comment above it, which is what makes it survive review. The comments in
this repo *are* the auditor-facing reasoning, so a false one is worse than none.
Every safety claim gets a counterexample test, built from a stranger's input
rather than the happy path, written *before* the claim goes in a comment.

**Over-report; never erase.** A claim may not consume a record the engine cannot
prove is the agent's. Corroborating a record removes it from the unclaimed
accounting, so a wrong match does not merely mislead — it makes a stranger's
production action cease to exist in the report. When in doubt the join reports
too much. See the `consumable` guard in `internal/corroborate/matcher.go` and the
regressions around it.

## Before you open a PR

```sh
go build ./...
go vet ./...
gofmt -l .                      # must print nothing
go test ./... -count=1 -race    # must stay green under -race
```

CI additionally runs a fuzz smoke over the untrusted-input parsers, `govulncheck`,
an SBOM regeneration, and `osv-scanner`. All hard-fail. If you touch a parser that
reads a customer's log, it needs a fuzz target.

Live-validation tests are env-gated and skip by default (`CROSSBEARING_LIVE`,
`CROSSBEARING_TRANSCRIPT`, `CROSSBEARING_K8S_AUDIT`, and friends). The suite is
hermetic without them.

## Pull requests

**One logical change per PR, squash-merged.** `main` is linear: every commit is
one PR. Author the squash message yourself — never let GitHub's default
list-of-commits through. The squash message is the permanent record of the
change; branch commits are scratch.

Write it as documentation, not a changelog line: what changed, why, and what a
reader needs to know to audit it later. Scale to scope. For a bug fix, state the
bug, the root cause, and the fix.

Every commit carries:

```
Co-authored-by: stxkxsbot <275011021+stxkxsbot@users.noreply.github.com>
```

Commits are SSH-signed, and squash merges are authored server-side by GitHub, so
every line of `main` verifies. Squash is the only merge mode enabled — rebase
merges re-create commits unsigned, and merge commits bury the reasoning behind
"Merge pull request #N".

## The evidence format is a contract

`internal/pack` emits `aep/1`. The verifier is a **separate, MIT-licensed,
zero-dependency repository** (`crossbearing/verify`) that never imports this one
— it re-derives the canonical bytes from the document itself. That independence
is the product, not a nicety: evidence has to verify without trusting the engine
that produced it, or its license.

There is **no verifier in this repo**, and its absence is load-bearing. A
second one here would undermine that independence while looking useful.

Any change to the `aep/1` payload shape is breaking for that repo. Version-bump
the format and update both repos together.

## Security

Report vulnerabilities privately — see the organization
[security policy](https://github.com/crossbearing/.github/blob/main/SECURITY.md).
Please don't open a public issue for a vulnerability.

## License

[FSL-1.1-ALv2](LICENSE.md) — source-available, converting to Apache 2.0 two years
after each release. There are no per-file license headers; the repo-level
`LICENSE.md` governs. By contributing you agree your contribution is licensed
under those terms.
