package corroborate

import "strings"

// Agents do not type the commands in the textbooks. They write scripts,
// and scripts reach a CLI through two indirections that a literal
// "is token[0] the string kubectl" test does not survive:
//
//	K=/usr/local/bin/kubectl
//	$K -n monitoring rollout restart ds/alloy
//
// Both appear in real agent transcripts — the lines above are verbatim
// from the run that restarted three production workloads on dev-eks. The
// audit log recorded all three patches; the claim side translated none of
// them, because "$K" is not "kubectl". Every claim the translators cannot
// read is a claim the join never sees, which turns a corroborated finding
// into an unclaimed record: the engine reports the agent did something it
// never admitted to, when in fact it said so plainly and we could not
// parse it. Failing closed is right when a command is ambiguous; it is not
// right when the command is perfectly clear and merely written in a shell
// dialect we declined to read.
//
// shellCommands resolves both indirections and hands the translators
// segments whose command position is directly comparable to a CLI name.
// It stays deliberately small: whole-token variable expansion and nothing
// else. Arithmetic, command substitution, globbing, and parameter
// defaulting all remain untranslatable, and a segment that still holds an
// unresolved "$" simply fails to match a CLI, as before.
func shellCommands(cmd string) [][]string {
	segs := shellSegments(cmd)
	vars := make(map[string]string)
	out := make([][]string, 0, len(segs))
	for _, seg := range segs {
		seg = expandVars(seg, vars)
		if rest, declared := declarations(seg, vars); declared {
			// A segment that only assigns (K=…, export AWS_PROFILE=…)
			// defines no command. Its bindings are now in vars.
			continue
		} else {
			seg = rest
		}
		if len(seg) > 0 {
			out = append(out, seg)
		}
	}
	return out
}

// declarations records the variable assignments a segment makes and
// returns whatever command follows them. It reports true when the segment
// was assignments and nothing else.
//
// Only a standalone assignment persists — that is the shell's rule, and it
// matters here: in `AWS_PROFILE=prod aws s3 rm …` the assignment is scoped
// to that one command, and letting it leak into later segments could bend
// a subsequent command's meaning. Prefix assignments are therefore parsed
// and dropped, exactly as the translators already did.
func declarations(seg []string, vars map[string]string) (rest []string, declaredOnly bool) {
	i := 0
	for i < len(seg) && (seg[i] == "export" || seg[i] == "declare" || seg[i] == "local") {
		i++
	}
	assigns := 0
	for i < len(seg) && isEnvAssign(seg[i]) {
		assigns++
		i++
	}
	if i < len(seg) {
		return seg, false // assignments prefixed a command: command-scoped, not persistent
	}
	if assigns == 0 {
		return seg, false // not a declaration at all (a bare "export", say)
	}
	for _, t := range seg[:i] {
		if eq := strings.IndexByte(t, '='); eq > 0 {
			vars[t[:eq]] = t[eq+1:]
		}
	}
	return nil, true
}

// expandVars substitutes whole-token $NAME and ${NAME} references. An
// unquoted expansion word-splits in the shell — K="kubectl --context dev"
// yields three tokens, not one — so the value is split on whitespace and
// spliced in, which is what makes the command land in command position.
// A name we never saw assigned is left verbatim: it may be inherited from
// the environment, and guessing at it could translate a command we cannot
// actually read.
func expandVars(seg []string, vars map[string]string) []string {
	if len(vars) == 0 {
		return seg
	}
	out := make([]string, 0, len(seg))
	for _, t := range seg {
		name, ok := varRef(t)
		if !ok {
			out = append(out, t)
			continue
		}
		val, known := vars[name]
		if !known {
			out = append(out, t)
			continue
		}
		out = append(out, strings.Fields(val)...)
	}
	return out
}

// varRef reports the name in a token that is entirely one variable
// reference ("$K", "${K}"). Anything else — "$K/bin", "a$K" — is not a
// command-position reference worth resolving.
func varRef(t string) (string, bool) {
	if len(t) < 2 || t[0] != '$' {
		return "", false
	}
	name := t[1:]
	if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
		name = name[1 : len(name)-1]
	}
	if name == "" {
		return "", false
	}
	for _, r := range name {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "", false
		}
	}
	return name, true
}

// isCommand reports whether a command-position token invokes the named
// CLI. Scripts routinely call a tool by path — `/usr/local/bin/kubectl`,
// `./aws` — and the trailing element is what decides which binary runs.
// Matching the basename (rather than a suffix) keeps "mykubectl" and
// "kubectl-argo-rollouts" from passing as kubectl.
func isCommand(token, name string) bool {
	if i := strings.LastIndexByte(token, '/'); i >= 0 {
		token = token[i+1:]
	}
	return token == name
}
