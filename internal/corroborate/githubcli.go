package corroborate

import "strings"

// GHCLIRecordOps parses a shell command and returns the github-audit
// record-vocabulary operations its `gh` and `git push` invocations would
// produce. Attested-only, fail closed — the same contract as the aws and
// kubectl translators.
//
// `git push` is the load-bearing entry: it is how most agent work
// actually reaches GitHub, and the org audit log records it as git.push.
func GHCLIRecordOps(command string) []string {
	var ops []string
	for _, seg := range shellSegments(command) {
		if op, ok := ghInvocation(seg); ok {
			ops = append(ops, op)
		}
		if gitPushInvocation(seg) {
			ops = append(ops, "github-audit:git.push")
		}
	}
	return ops
}

// ghActions maps `gh <command> <subcommand>` pairs to org audit-log
// actions. Only pairs whose audit action is attested belong here.
var ghActions = map[string]string{
	"pr merge":    "github-audit:pull_request.merge",
	"pr create":   "github-audit:pull_request.create",
	"pr close":    "github-audit:pull_request.close",
	"pr reopen":   "github-audit:pull_request.reopen",
	"repo create": "github-audit:repo.create",
	"repo delete": "github-audit:repo.destroy",
	"repo rename": "github-audit:repo.rename",
}

func ghInvocation(tokens []string) (string, bool) {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || tokens[i] != "gh" {
		return "", false
	}
	i++

	var bare []string
	for ; i < len(tokens) && len(bare) < 2; i++ {
		if strings.HasPrefix(tokens[i], "-") {
			continue
		}
		bare = append(bare, tokens[i])
	}
	if len(bare) < 2 {
		return "", false
	}
	op, ok := ghActions[bare[0]+" "+bare[1]]
	return op, ok
}

// gitPushInvocation reports whether the segment is a `git push` in
// command position. Value-taking git globals (-C, -c) are skipped so
// `git -C /repo push origin main` translates.
func gitPushInvocation(tokens []string) bool {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || tokens[i] != "git" {
		return false
	}
	i++
	for ; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-C" || t == "-c" {
			i++
			continue
		}
		if strings.HasPrefix(t, "-") {
			continue
		}
		return t == "push"
	}
	return false
}
