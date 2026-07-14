package corroborate

import (
	"fmt"
	"strings"
)

// BashOperation renders a shell command as the claim vocabulary's Bash(…)
// operation: a report label, capped and single-line. It is a SUMMARY, not an
// identity — distinct commands routinely share one (every agent script opens
// `export PATH=…`), which is why ClaimKey exists and why nothing may key on
// this string.
//
// It lives here rather than in an ingester because both claim streams build it:
// a Claude Code `Bash` tool call and a Bedrock shell tool are the same claim in
// two vocabularies, and they must render identically or the same command
// translates two ways.
func BashOperation(cmd string) string {
	if i := strings.IndexByte(cmd, '\n'); i >= 0 {
		cmd = cmd[:i]
	}
	const max = 100
	if len(cmd) > max {
		return cmd[:max] + "…"
	}
	return cmd
}

// ExpandShellClaim turns one executed tool call into the claims it actually
// made.
//
// A tool call yields one claim, except a shell command that runs more than one
// recognized CLI invocation. That is a script, and a script claims each of its
// commands separately. Modeling it as a single claim leaves the join 1:1 against
// the many records it produced: one corroborates and the rest read as unclaimed
// — the engine reporting hidden work that the agent wrote down in plain sight.
// On the dev-eks corpus that was 1,560 real commands modeled as 379 claims.
//
// This is deliberately NOT in an ingester. Both claim streams emit Bash(…)
// claims over the same CLI translators — claudecode from a transcript, bedrock
// from a model-invocation log — and an agent that runs a forty-command script
// has the same bug on whichever stream observes it. bedrock exists precisely for
// kagent-style agents that emit no transcript, which is the Kubernetes path,
// which is where the scripts are. Fixing this per-ingester fixes it for whoever
// happened to be holding the bug.
//
// The split claims share the tool call's provenance verbatim: locator and digest
// still point at the one line where every one of these commands is written, so
// each stays independently re-fetchable. Their IDs suffix the tool-use ID with
// the invocation's position, which keeps them unique — the matcher consumes a
// record per claim, so two claims sharing an ID would collapse back into one.
//
// A shell command with no recognized invocation stays exactly one claim. It may
// still have done something real (a terraform apply, a curl to some API), and
// dropping it would erase the claim rather than fail to corroborate it.
//
// Known imprecision: a command inside a branch or loop that never ran is still
// claimed, because the tool_result proves the script ran, not which lines it
// reached. `if [ "$ENV" = staging ]; then kubectl delete deploy/api; fi` in prod
// mints a claim for a deletion that never happened.
//
// This comment used to assert the unsafe direction was "impossible", and it was
// wrong: the matcher correlated on time and operation alone, so a phantom claim
// could consume a stranger's production deletion, report it Corroborated, and
// erase the stranger's unattributed action. A later attempt to PROVE the agent's
// credential inside the join was also unsound — it proved credentials from
// coincidence. Neither guarantee should have been written before it was tested.
//
// What actually makes over-claiming safe is the matcher's `consumable` guard: a
// production record is consumable only when its ownership is POSITIVELY
// established — the record names THE AGENT SESSION'S OWN human (not merely some
// human: a stranger's impersonation record names one too), or the operator
// scoped the run to the credential (MatchPolicy.AgentRecord). An over-claim
// absent that evidence falls to UnrecordedClaim, not Corroborated — the
// direction this engine is allowed to be wrong in.
//
// Heredoc bodies and command substitutions are excluded upstream (stripHeredocs,
// hasUnresolved): those are not over-claims but claims about text that was never
// a command at all.
func ExpandShellClaim(c Claim) []Claim {
	if !strings.HasPrefix(c.Operation, "Bash(") || c.Target == "" {
		return []Claim{c}
	}
	invocations := CLIInvocations(c.Target)
	if len(invocations) <= 1 {
		return []Claim{c}
	}
	out := make([]Claim, 0, len(invocations))
	for i, inv := range invocations {
		split := c
		split.ID = fmt.Sprintf("%s#%d", c.ID, i)
		split.Operation = "Bash(" + BashOperation(inv) + ")"
		split.Target = inv
		out = append(out, split)
	}
	return out
}
