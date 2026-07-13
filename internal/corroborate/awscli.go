package corroborate

import (
	"strings"
)

// This file bridges claim vocabulary to record vocabulary for one common
// case: agent shell commands that invoke the AWS CLI. A claim like
//
//	Bash(aws sts get-caller-identity --profile x)
//
// can legitimately produce the CloudTrail record sts:GetCallerIdentity,
// and the MatchPolicy.OperationMap entry saying so is derivable from the
// command itself. Per the Claim contract, this mapping lives matcher-side:
// ingesters report claims in their own vocabulary and never guess records.
//
// The translation is deliberately conservative: a command we cannot
// confidently parse contributes nothing, which downstream means "not
// record-corroborable" rather than a wrong corroboration.

// cliTranslators are the per-CLI claim→record vocabulary derivations,
// one per record stream the engine ingests. Each fails closed on its own.
var cliTranslators = []func(string) []string{
	AWSCLIRecordOps,  // aws …          → CloudTrail vocabulary
	KubectlRecordOps, // kubectl …      → k8s-audit vocabulary
	GHCLIRecordOps,   // gh …, git push → github-audit vocabulary
	GcloudRecordOps,  // gcloud …       → gcp-audit vocabulary
	AzRecordOps,      // az …           → azure-activity vocabulary
}

// ClaimKey is the OperationMap key that identifies what a claim actually
// did. For most claims that is the Operation itself — "mcp:github:
// create_pull_request" names one action.
//
// A shell claim is different, and the difference is load-bearing. Its
// Operation is a human-readable summary — the command's first line, capped
// for the report — while the command it ran lives in Target. Agents write
// scripts, and scripts share first lines:
//
//	Bash(export PATH="/opt/homebrew/bin")   →  … $K -n argocd get secret x
//	Bash(export PATH="/opt/homebrew/bin")   →  … $K -n prod delete deploy/api
//
// Keyed by Operation, those two collapse into one entry whose record-ops
// are the UNION of both — and the matcher will then happily corroborate
// the secret-read claim against the deletion record, because the union says
// that operation is a legitimate product of that claim. A false
// corroboration is the worst verdict this engine can reach: it does not
// merely lose a finding, it reports a divergence as accounted for, which is
// the precise opposite of the job. Keying on the command keeps every
// distinct command's translation to itself.
func ClaimKey(c Claim) string {
	if strings.HasPrefix(c.Operation, "Bash(") && c.Target != "" {
		return c.Target
	}
	return c.Operation
}

// DeriveOperationMap builds OperationMap entries for claims whose targets
// are shell commands invoking CLIs whose record streams the engine
// ingests (aws, kubectl, gh, git push). Entries are keyed by ClaimKey, so
// each distinct command carries its own translation. Claims that derive no
// entries are simply absent — callers use presence in the map to scope
// which claims can seek records at all.
func DeriveOperationMap(claims []Claim) map[string][]string {
	m := make(map[string][]string)
	for _, c := range claims {
		if !strings.HasPrefix(c.Operation, "Bash(") {
			continue
		}
		key := ClaimKey(c)
		for _, translate := range cliTranslators {
			for _, op := range translate(c.Target) {
				if !contains(m[key], op) {
					m[key] = append(m[key], op)
				}
			}
		}
	}
	return m
}

// AWSCLIRecordOps parses a shell command and returns the record-vocabulary
// operations ("sts:GetCallerIdentity") its AWS CLI invocations would
// produce. Unparseable or non-API invocations (aws configure, aws help,
// s3 high-level commands like cp/sync, single-word subcommands) yield
// nothing.
func AWSCLIRecordOps(command string) []string {
	var ops []string
	for _, seg := range shellCommands(command) {
		if op, ok := awsInvocation(seg); ok {
			ops = append(ops, op)
		}
	}
	return ops
}

// localServices are aws-CLI subcommands that never call a service API (or
// whose calls this translator cannot map): they must not generate record
// expectations.
var localServices = map[string]bool{
	"configure": true,
	"help":      true,
	"history":   true,
	// s3 high-level commands (ls/cp/sync/...) fan out to API calls this
	// translator does not model; s3api maps 1:1 and is handled below.
	"s3": true,
}

// valueFlags are global aws-CLI flags that consume the next token.
var valueFlags = map[string]bool{
	"--profile": true, "--region": true, "--output": true, "--query": true,
	"--endpoint-url": true, "--color": true, "--ca-bundle": true,
	"--cli-read-timeout": true, "--cli-connect-timeout": true,
}

// commandWrappers may legitimately precede "aws" in command position.
var commandWrappers = map[string]bool{
	"sudo": true, "time": true, "env": true, "command": true, "nohup": true, "exec": true,
}

// awsInvocation inspects one command segment. The "aws" token must be in
// command position (only env assignments and wrappers before it) — that,
// plus quote-aware tokenization, keeps prose that merely mentions aws
// (commit messages, echo strings) from minting fake vocabulary.
func awsInvocation(tokens []string) (string, bool) {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || !isCommand(tokens[i], "aws") {
		return "", false
	}
	i++

	var service, operation string
	for ; i < len(tokens); i++ {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if valueFlags[t] && !strings.Contains(t, "=") {
				i++ // skip the flag's value too
			}
			continue
		}
		if service == "" {
			service = t
			continue
		}
		operation = t
		break
	}

	if localServices[service] {
		return "", false
	}
	if service == "s3api" {
		service = "s3"
	}
	if !isKebabLower(service) || !isKebabLower(operation) || !strings.Contains(operation, "-") {
		// Real API subcommands are verb-noun kebab ("get-caller-identity");
		// requiring the hyphen rejects both prose and the streaming/login
		// style commands (logs tail, sso login) that don't map cleanly.
		return "", false
	}
	return service + ":" + kebabToEventName(operation), true
}

// acronyms that AWS event names upper-case as units; everything else is
// plain title case. A miss here means a mapping that fails closed (no
// corroboration), never a wrong one.
var acronyms = map[string]string{
	"mfa": "MFA", "ssh": "SSH", "vpc": "VPC", "db": "DB", "url": "URL",
	"acl": "ACL", "oidc": "OIDC", "saml": "SAML", "sse": "SSE",
}

// kebabToEventName turns a CLI subcommand into the CloudTrail eventName
// casing: lookup-events → LookupEvents, describe-db-instances →
// DescribeDBInstances, list-objects-v2 → ListObjectsV2.
func kebabToEventName(op string) string {
	parts := strings.Split(op, "-")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue // defense in depth; isKebabLower already rejects "--"
		}
		if a, ok := acronyms[p]; ok {
			b.WriteString(a)
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

func isEnvAssign(t string) bool {
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return false
	}
	for _, r := range t[:eq] {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func isKebabLower(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	// Consecutive hyphens ("describe--instances") are not a real CLI
	// subcommand; rejecting them here fails closed AND keeps every part
	// kebabToEventName splits on non-empty.
	return s[0] != '-' && s[len(s)-1] != '-' && !strings.Contains(s, "--")
}

// shellSegments tokenizes a shell command quote-aware and splits it into
// command-position segments at ; | & newlines and subshell boundaries.
// Quoted strings become single tokens, so a commit message or echo string
// that mentions "aws something" cannot land "aws" in command position.
func shellSegments(cmd string) [][]string {
	var (
		segs    [][]string
		cur     []string
		tok     strings.Builder
		inTok   bool
		quote   byte // 0, '\'', '"'
		escaped bool
	)
	flushTok := func() {
		if inTok {
			cur = append(cur, tok.String())
			tok.Reset()
			inTok = false
		}
	}
	flushSeg := func() {
		flushTok()
		if len(cur) > 0 {
			segs = append(segs, cur)
			cur = nil
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case escaped:
			tok.WriteByte(c)
			inTok = true
			escaped = false
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				tok.WriteByte(c)
			}
		case quote == '"':
			switch c {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				tok.WriteByte(c)
			}
		case c == '\\':
			escaped = true
		case c == '\'' || c == '"':
			quote = c
			inTok = true // empty quotes still make a token
		case c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')' || c == '`':
			flushSeg()
		case c == ' ' || c == '\t':
			flushTok()
		default:
			tok.WriteByte(c)
			inTok = true
		}
	}
	flushSeg()
	return segs
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
