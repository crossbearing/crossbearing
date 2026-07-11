# Design spec — agent-suspect scoping + two-tier attribution report

**Status:** design, not yet built. This is the single engine task that makes the
AWS attribution audit safe and legible on a noisy *real customer* account — the
MLP-launch gate (see `~/codes/crossbearing/go-to-market/mlp-definition.md`).

> This spec is the **revised** design: it was produced by a grounding pass over
> `internal/{attribute,corroborate,ingest/cloudtrail,render}` + `cmd/crossbearing`,
> a design pass, and **two adversarial reviews** (a false-negative/safe-direction
> lens and an over-claim/explainability lens). Both reviews returned
> *needs-revision* and their corrections are folded in here; the "What the review
> corrected" section at the end records why, so the reasoning survives.

## Why — the real noise problem (corrected)

The intuition was "real accounts drown the headline under service-linked-role
noise (SSM, ResourceExplorer)." The code says otherwise, and the difference
matters:

- The join already drops service-linked noise. `matcher.go:104`:
  `if !inWindow && r.SourceIdentity == "" { continue }` — a record outside every
  agent session window with no SourceIdentity is skipped. Service-linked-role
  sessions (no SourceIdentity, not inside an agent window) never become findings.
- So tier-1 unattributed findings are **already** scoped to records that are
  *in an agent session window* and `ProductionTouching` (`matcher.go:109`, gated
  by `--production-match`).
- The actual legibility gap is two things:
  1. **`--principal` is the only noise control today, and it's coarse** — it
     filters records *pre-Join* (`cmd/crossbearing/main.go:263-271`), which
     **suppresses evidence** before it's ever joined.
  2. **Same-principal / same-window bystander activity** can't be separated by
     principal alone — the dogfood run (CLAUDE.md item 2.5) caught 3
     `s3:CreateBucket` by *other* activity on the same SSO principal inside the
     agent window. Coarse principal scoping can't tell the agent's action from a
     bystander sharing the credential.

**The fix:** stop relying on `--principal` to suppress; keep the join **total**;
add a **post-Join, fail-open, two-tier labeling pass** that surfaces the records
we can *positively tie to the agent* and labels everything else honestly.

## Core approach

- A pure classifier `attribute.AgentSuspect(r corroborate.Record, idx ScopeIndex)
  (bool, reason string)` — a **separate downstream pass**. The cloudtrail
  ingester and `corroborate.Join` are untouched; the **Agent Evidence Package is
  built from the complete finding set as today** (`pack` consumes `rep.Findings`
  directly — the signed evidence stays total and honest).
- **Two views over the same findings**, never a filter that removes evidence:
  - **Tier-1** — *every* unattributed action (today's behavior, unchanged). This
    is what gets signed.
  - **Tier-2** — the subset positively fingerprinted to an agent, **each card
    carrying its classification reason** ("why we flagged this for you").
- **Fail-OPEN.** A record enters tier-2 only on a *named positive signal*; absent
  one it stays fully visible in tier-1. The classifier can only **add attention,
  never subtract a record** from the complete trail.
- **Never asserts a human.** `AgentSuspect` answers "is this worth the auditor's
  eye," never "who did it." `Human` is still set *only* by the proven attribution
  ladder (SourceIdentity / session tags / impersonation). A tier-2 card with no
  human still renders UNATTRIBUTED, identical to tier-1.

## The classifier — signals (revised)

Checked **negative-first** so noise can never reach a positive by accident.

**Negative — provably-not-agent (stays tier-1 only):**

- **Service-linked role:** `roleFromPrincipal(r.Principal)` has prefix
  `AWSServiceRole`, or `r.Principal` contains `:assumed-role/aws-service-role/`.
  AWS-reserved; a customer cannot create these.
- **AWS-service callers** need no special branch: they carry no assumed-role ARN,
  so `roleFromPrincipal` returns `""`, which can never match a positive signal —
  they stay tier-1 automatically. *(Do not add a `PrincipalType == "AWSService"`
  check: that field does not exist on `corroborate.Record`. Relying on the empty
  role name avoids plumbing a phantom field.)*

**Positive — promote to tier-2 (strongest first), each with its own reason:**

1. **PROVEN-CREDENTIAL (evidence, not heuristic).** `r.AccessKeyID` is in the
   proven-key set — keys a `ConfidenceCorroborated` binding tied to an agent claim
   session (`attribute.Bind`'s `proofByKey`, `bind.go:67-80`, exposed via a new
   `ProvenKeys` helper). Reason: *"credential session proven to be the agent's by
   corroborated finding &lt;id&gt;."*
   **Scope caveat (honest):** this proves the *credential session* is the agent's,
   **not** that every individual record on that key was the agent's action
   (CLAUDE.md item 3 — the `ListBuckets`/same-key caveat). It correctly flags the
   session for attention; it does not assert per-action attribution. Keep it
   strongest, but the doc-comment must not claim per-action certainty.
2. **OPERATOR-PATTERN (opt-in, operator-asserted).** `sessionNameFromARN(r.Principal)`
   matches a caller-supplied `--agent-session-pattern` (default empty → inert).
   Reason: *"session name &lt;name&gt; matches operator-supplied pattern &lt;pat&gt;."*
   This is **operator-asserted scoping, labeled as such — not engine-derived
   evidence.**
   *(This replaces a dropped signal that compared the ARN session name against
   `Session.Agent`. That was a category error: `Session.Agent` is the **tool name**
   — `claudecode` stamps `"claude-code"`, `bedrock` stamps `"bedrock"` — never the
   STS session name, so the comparison never honestly fires.)*
3. **PROGRAMMATIC (weak hint, last; needs `Record.UserAgent` — see Files).**
   `UserAgent` is an SDK/CLI string, not a console or service endpoint. Reason:
   *"programmatic (non-console) call"* — it distinguishes programmatic from console
   and **nothing more.** Not *"agent fingerprint"*: a human's own `aws-cli` carries
   the same user-agent, and the SSO-cache lesson (CLAUDE.md item 3) is that
   user-agent cannot separate a human from an agent.

## The two-tier report

- **Tier-1 (unchanged):** section 01, *"Production-touching actions with no named
  human."* Full unattributed set; the count is the full `N`. This is what the AEP
  signs.
- **Tier-2 (new section 01a, rendered above tier-1):** *"Agent-suspect:
  unattributed, in-window, positively fingerprinted."* The `M` findings where
  `AgentSuspect()==true`, each with its `Reason` line (distinct from the finding's
  own `Why`). A new summary-strip stat cell shows `agent-suspect M`.
- **Honest arithmetic (corrected).** The report shows `N` unattributed, `M`
  agent-suspect. **`N − M` is NOT "background noise."** Because the join already
  dropped out-of-window no-SourceIdentity records (`matcher.go:104`), `N − M` is
  *in-window production actions we could not positively fingerprint* — **look
  harder, still first-class, shown in full directly below.** A *separate, small*
  "service-linked (set aside)" count covers only records that actually hit the
  hard negative exclusion. The 01a lede states the rule in one sentence; **no
  record is ever absent from both tiers.**
- The **text report** gets the same partition: after the existing kind-ordered
  dump (unchanged), an `AGENT-SUSPECT (M of N unattributed)` block lists the
  tier-2 findings with reasons.

## Files

| File | Change |
|---|---|
| `internal/attribute/scope.go` *(new)* | `ScopeIndex` + `NewScopeIndex(...)` + `AgentSuspect(r, idx) (bool, string)`. Pure, stdlib-only, negative-first/positive-second, default false. |
| `internal/attribute/scope_test.go` *(new)* | Table tests pinning **every branch and its reason string** (AWSServiceRole→not; aws-service-role path→not; proven key→suspect+names finding; operator-pattern→suspect; SDK UA→suspect "programmatic"; service-endpoint UA→not; unrecognized name + no proof→**not** (fail-open); empty Record→not, no panic). Locks the auditor-explainability contract. |
| `internal/attribute/bind.go` | Add a `ProvenKeys(findings) map[string]string` sibling that reuses `proofByKey` (`bind.go:67-80`). **Do not change `Bind`'s signature.** |
| `cmd/crossbearing/main.go` | Add `--agent-session-pattern` flag (default empty); after Join+Bind build `ScopeIndex` and compute the tier-2 subset; wire into text + html render. **Do NOT scope `checkRoleConventions`** (see below). |
| `internal/render/html.go` | Add `UnattributedAgentSuspect []card` + `card.Reason` + `HasAgentSuspect()` + a 6th stat cell. `BuildView` takes an `isAgentSuspect func(*corroborate.Record)(bool,string)` predicate; the Unattributed loop (`html.go:163-183`) populates tier-1 unconditionally **and** appends to tier-2 when the predicate fires. Keep `Render`'s signature via a thin wrapper defaulting the predicate to always-false. |
| `internal/render/report.html.tmpl` | Add section 01a (gated by `HasAgentSuspect`) above section 01; per-card `Reason` line + one-sentence lede. Section 01 unchanged. |
| `internal/corroborate/types.go` | Add `Record.UserAgent string` — **optional, only after confirming the `internal/pack` AEP impact** (additive + `verify/`-tolerant per the `controls.go` precedent, or not embedded). Signals 1+2 work without it; defer signal 3 if unsafe. |
| `internal/ingest/cloudtrail/ingest.go` | In `record()` (`ingest.go:181-205`) forward `ex.UserAgent` into `Record.UserAgent`. One line; only if the field lands. |
| ARN parsing | **One canonical source.** `sessionNameFromARN` is unexported in `cloudtrail/event.go:88`; `roleFromPrincipal` is in `main.go:420`. Do not fork a third copy into `scope.go` — export/lift to one home and have callers delegate. |

## Build sequence (small, independently shippable)

1. `scope.go` + `scope_test.go` + `ProvenKeys` — signals 1+2 only; UA deferred
   behind an empty-string check. Self-contained, nothing user-visible. `go test
   ./internal/attribute -race`.
2. `cmd/main.go` wiring → **text** tier-2 block first (easiest to eyeball against
   the dogfood session). **Leave `checkRoleConventions` total.** `go build ./...
   && go test ./... -race`.
3. `render` html.go + template section 01a + stat cell; thread the predicate with
   an always-false default so existing render tests stay green; **update the fab
   golden** (`TestFabDemo_DeterministicOutput`). `go test ./internal/render -race`.
4. *(Only after the pack/AEP check)* `Record.UserAgent` + forwarding + flip on
   signal 3. `go test ./... -race`; gofmt + vet clean.
5. Re-run `./demo/fab/run.sh --format html` and the dogfood cloudtrail run:
   tier-1 count unchanged; tier-2 surfaces the proven-credential agent records
   with reasons; `N − M` labeled as *unfingerprinted in-window*, not noise.

## Guardrails

- **Ingester stays total.** No change to `cloudtrail/session.go` or to `Join`. The
  only ingest edit forwards an existing field (UserAgent) — adds data, drops
  nothing.
- **Never asserts a human.** `AgentSuspect` returns `(bool, reason)`; `Human`
  remains set only by the proven attribution ladder.
- **Fail-open.** Promote to tier-2 only on a named positive signal; the two hard
  exclusions are provably-not-agent (AWS-reserved), not guesses — and even those
  records stay in tier-1.
- **Evidence over heuristic.** The strongest signal (proven credential) is carried
  straight from `Bind`'s `proofByKey`; the heuristic signals rank strictly below
  it and each name their own reason.
- **Transparency of the boundary.** Show `N`, `M`, and the small set-aside count;
  the full tier-1 list is one disclosure below. Every tier-2 card states its
  reason verbatim.
- **Pack unchanged / total.** The AEP is built from `rep.Findings` as today. Tier-2
  is render-only; it is never the thing that gets signed.
- **Minimum new surface, lean go.sum.** One optional field, one new file, one
  render sub-slice + stat + template section. Stdlib only.

## What the adversarial review corrected

The first-pass design was bundled with changes that broke the very guarantees it
claimed. Recorded so the reasoning isn't lost:

1. **Don't scope `checkRoleConventions` to agent-suspect principals.** *(blocker,
   false-negative lens)* It would silently drop the **missing-SourceIdentity
   trust-policy gap** — the product's headline finding — on exactly the records the
   heuristic is weakest on (an agent producing UnclaimedRecord/Unattributed has no
   corroboration → no proven key → scores `AgentSuspect=false`, and its ARN parses
   cleanly so the can't-classify fallback doesn't catch it). `iam:GetRole` is
   already deduped per role name (`main.go:389-394`), so cost is bounded by
   distinct roles, not events — keep it total. Split out of this work.
2. **Dropped the `Session.Agent` name-match signal.** *(blocker, over-claim lens)*
   `Session.Agent` is the tool name (`"claude-code"`/`"bedrock"`), not the STS
   session name — the comparison is a category error that never honestly fires.
   The only honest session-name signal is the operator-supplied pattern, labeled
   as operator-asserted.
3. **Dropped the `PrincipalType == "AWSService"` exclusion.** *(blocker)* That
   field doesn't exist on `Record`; rely on `roleFromPrincipal()==""` keeping
   AWS-service callers in tier-1 — no phantom field, no extra plumbing.
4. **Relabeled `N − M` honestly.** *(major, both lenses)* The join drops
   service-linked noise upstream, so `N − M` is *unfingerprinted in-window
   production activity* — "look harder" — **not** "background noise safely set
   aside." Calling it noise would mislabel the auditor's most important records.
5. **Weakened the user-agent reason** to *"programmatic (non-console) call,"* not
   *"agent fingerprint"* — a human's `aws-cli` carries the same UA.
6. **Softened proven-credential** to session-level identity, not per-action
   certainty (the same-key caveat).
7. **One canonical ARN parser**, not a third forked copy.

## Open questions

- **Is `corroborate.Record` embedded verbatim in the aep/1 payload, or
  summarized?** Decides whether `Record.UserAgent` is an additive aep/1 change
  requiring a lockstep `verify/` update (CLAUDE.md item 4). Read `internal/pack`
  before step 4.
- **`AWSReservedSSO_*` (human-SSO) roles:** do **not** hard-exclude them — an agent
  can run under an SSO-assumed role (the dogfood run did). Let the positive
  signals decide (hard-excluding risks dropping a real agent finding — wrong
  direction). With signal 2 gone and signal 3 downgraded to "programmatic," an
  SSO+CLI human action is flagged honestly (it *is* a non-console call) without
  claiming it's the agent.
- **`--agent-session-pattern`:** substring (matches the existing `--principal` /
  `--production-match` convention) unless a partner needs regex.
- **Text `--tier` suppression flag:** default to always-show-both (honesty
  default); a terse operator view is separate, later work and must never be the
  default.
