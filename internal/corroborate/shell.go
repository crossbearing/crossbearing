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
	segs := shellSegments(stripHeredocs(cmd))
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
		if seg = stripRedirections(seg); len(seg) > 0 {
			out = append(out, seg)
		}
	}
	return out
}

// stripHeredocs removes heredoc BODIES before lexing. A heredoc body is data
// being written somewhere, not commands being run:
//
//	cat > deploy.sh <<'EOF'
//	aws s3api delete-bucket --bucket prod-payments
//	EOF
//
// The agent wrote a file. It did not delete a bucket. With no heredoc state the
// lexer read that middle line as a command segment and the engine MINTED a claim
// from it — and a claim for a command that never ran can be corroborated by
// somebody else's record, which erases their divergence and reports the agent as
// having done a thing it did not do. Writing script files by heredoc is routine
// agent behaviour, so this is not an exotic input.
//
// The delimiter line itself and the command that opened the heredoc both stay:
// `cat > deploy.sh` is a real command, merely one no record stream holds.
func stripHeredocs(cmd string) string {
	if !strings.Contains(cmd, "<<") {
		return cmd // the overwhelmingly common case, at no cost
	}
	lines := strings.Split(cmd, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		out = append(out, lines[i])
		delim, ok := heredocDelimiter(lines[i])
		if !ok {
			continue
		}
		// Swallow the body up to (and including) the delimiter line.
		for i+1 < len(lines) {
			i++
			if strings.TrimSpace(lines[i]) == delim {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// heredocDelimiter finds the word a `<<WORD` / `<<-WORD` / `<<'WORD'` redirection
// will read until. `<<<` is a here-STRING — one line, no body — and is not one.
func heredocDelimiter(line string) (string, bool) {
	i := strings.Index(line, "<<")
	if i < 0 {
		return "", false
	}
	rest := line[i+2:]
	if strings.HasPrefix(rest, "<") { // <<< here-string: no body to swallow
		return "", false
	}
	rest = strings.TrimPrefix(rest, "-") // <<- strips leading tabs; same delimiter
	rest = strings.TrimLeft(rest, " \t")
	// The delimiter may be quoted (<<'EOF' / <<"EOF"); quoting only decides
	// whether the BODY expands, which is irrelevant — we are discarding it.
	rest = strings.TrimLeft(rest, "'\"")
	end := strings.IndexAny(rest, " \t'\"")
	if end >= 0 {
		rest = rest[:end]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

// stripRedirections drops I/O redirection from a segment: it plumbs the
// command's output and says nothing about what the command did. Left in, `2>`
// and a filename ride along as arguments, where a filename can be misread as a
// resource name and every reconstructed command line trails shell syntax.
//
// It strips ONLY a token that is redirection and nothing else — `>`, `>>`, `<`,
// `2>`, `&>`, `2>&1`. The lexer has already removed the quotes that made a token
// an argument, so `--field-selector '<expr>'` arrives here as the bare token
// `<expr>`, indistinguishable by prefix from a redirect. An earlier version
// matched on the leading characters and deleted it — silently dropping a real
// argument from the command, and therefore from the claim's Target, which is
// what the report shows and what every translator re-reads. A claim must never
// describe a command the agent did not run.
//
// The cost of the narrower rule is that an attached form (`>out.txt`, no space)
// survives as a stray token. That is the safe direction: a spurious token makes
// a translation fail closed, where a missing argument makes it silently wrong.
func stripRedirections(seg []string) []string {
	out := make([]string, 0, len(seg))
	for i := 0; i < len(seg); i++ {
		t := seg[i]
		if !isRedirectOperator(t) {
			out = append(out, t)
			continue
		}
		// An operator ending in `>` or `<` still wants its target: `> file`.
		// `2>&1` already names its destination and takes no next token.
		if c := t[len(t)-1]; c == '>' || c == '<' {
			i++
		}
	}
	return out
}

// isRedirectOperator reports whether a token is redirection syntax and NOTHING
// else: only digits, `&`, `-`, `<` and `>`, with at least one `<` or `>`. A
// token carrying any other character is an argument that merely begins like a
// redirect, and is left alone.
func isRedirectOperator(t string) bool {
	if t == "" {
		return false
	}
	arrow := false
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '<' || c == '>':
			arrow = true
		case (c >= '0' && c <= '9') || c == '&' || c == '-':
			// an fd number, a &-dup, or the &- close form
		default:
			return false
		}
	}
	return arrow
}

// CLIInvocations returns the individual CLI commands a shell command runs
// — one string per invocation that at least one translator recognizes,
// with variables resolved and in execution order.
//
// A shell claim is not one action. Agents work by writing scripts, and a
// script that calls kubectl forty times has claimed forty things; the
// transcript records it as a single Bash tool call only because that is the
// vehicle, not because it is one deed. Ingesting it as one Claim leaves the
// join 1:1 against forty records, so one corroborates and thirty-nine are
// reported unclaimed — the engine accusing an agent of hiding work it
// announced in the very same command. On the dev-eks corpus that was 1,560
// real commands modeled as 379 claims, and 902 records falsely unclaimed.
//
// Splitting here is what makes a claim mean one action again. Callers emit
// one Claim per invocation, all sharing the tool call's provenance: the
// evidence still points at exactly one transcript line, which is where every
// one of these commands is written down.
//
// Only recognized invocations are returned. A script's `echo`, `sleep` and
// `jq` lines produce no records in any stream, so claiming them would
// manufacture unrecorded-claim findings for work no audit log was ever going
// to hold.
//
// Over-claiming is possible and accepted: a command inside a branch that never
// ran is still returned, because the tool_result proves the script ran, not
// which lines it reached. That is SAFE only because the matcher will not let a
// claim consume a record it would otherwise have to report as Unattributed
// unless the agent's ownership of that record is positively established
// (MatchPolicy.AgentRecord). Without that guard an over-claim can be corroborated
// by a stranger's record, which erases the stranger's divergence — see the
// `consumable` guard in matcher.go.
//
// Text that was never a command at all is a different matter and is excluded
// outright: heredoc bodies (stripHeredocs) and segments left holding an
// unresolved `$` (hasUnresolved).
func CLIInvocations(command string) []string {
	var out []string
	for _, seg := range shellCommands(command) {
		if len(segmentOps(seg)) > 0 {
			out = append(out, joinTokens(seg))
		}
	}
	return out
}

// segmentOps translates ONE already-lexed command segment into the record
// operations it would produce, across every CLI the engine ingests.
//
// The per-CLI RecordOps entry points each lex the whole command themselves,
// which is right for their own contract but ruinous when a caller wants all of
// them: running the five translators over a command lexed the command five
// times, and CLIInvocations then re-lexed each reconstructed segment five times
// more. Working from tokens collapses that to one lex per command.
func segmentOps(seg []string) []string {
	if len(seg) == 0 || hasUnresolved(seg) {
		return nil
	}
	var ops []string
	if op, ok := awsInvocation(seg); ok {
		ops = append(ops, op)
	}
	ops = append(ops, kubectlInvocation(seg)...)
	if op, ok := ghInvocation(seg); ok {
		ops = append(ops, op)
	}
	if gitPushInvocation(seg) {
		ops = append(ops, "github-audit:git.push")
	}
	ops = append(ops, gcloudInvocation(seg)...)
	if op, ok := azInvocation(seg); ok {
		ops = append(ops, op)
	}
	return ops
}

// joinTokens rebuilds a runnable command line from resolved tokens, quoting
// any token the lexer would otherwise re-split. The result must re-parse to
// the tokens it came from, because it becomes the claim's Target and every
// translator reads it again from there.
func joinTokens(tokens []string) string {
	var b strings.Builder
	for i, t := range tokens {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(shellQuote(t))
	}
	return b.String()
}

// shellQuote single-quotes a token that would not survive re-lexing intact.
func shellQuote(t string) string {
	if t == "" {
		return "''"
	}
	if !strings.ContainsAny(t, " \t\n'\"\\;|&()<>$`*?#") {
		return t
	}
	// Single quotes protect everything but a single quote, which must leave
	// and re-enter the quoted run.
	return "'" + strings.ReplaceAll(t, "'", `'\''`) + "'"
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

// hasUnresolved reports whether any token still carries a `$` after expansion.
//
// It survives two things this translator cannot read: a variable it never saw
// assigned, and the remains of a command substitution (the lexer breaks
// `$(kubectl get pods -o name)` at the parenthesis, leaving a bare `$` behind).
// In both cases an argument of the command is UNKNOWN — `kubectl delete pod $`
// deletes a pod whose name we cannot name — and the reconstructed line would
// misdescribe what ran. A claim must never describe a command the agent did not
// run, so the segment contributes nothing.
//
// The substituted command itself is lexed as its own segment and is still
// claimed, which is right: it genuinely executed.
func hasUnresolved(seg []string) bool {
	for _, t := range seg {
		if strings.ContainsRune(t, '$') {
			return true
		}
	}
	return false
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
