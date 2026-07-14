// Package claudecode ingests Claude Code session transcripts (the JSONL
// files under ~/.claude/projects/<project>/<session-id>.jsonl) into the
// corroborate vocabulary: every executed tool call becomes a claim-side
// corroborate.Claim, and each session becomes a corroborate.Session.
//
// Transcripts are self-reported by construction — the agent's own process
// writes them — which is exactly why they sit on the claim side of the
// join. A tool_use block is the agent saying "I did this"; whether
// infrastructure agrees is the corroboration engine's question, not this
// package's.
//
// Only tool calls that actually returned a result count as claims: a
// tool_use with no matching tool_result was interrupted or denied before
// running, so the agent never did it. Errored results still count — a
// Bash command that exited non-zero still executed, and may well have
// touched infrastructure before failing.
package claudecode

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// entry is the slice of a transcript JSONL line this package reads.
// Transcript files carry many entry types (assistant, user, system,
// file-history-snapshot, ...); only assistant entries (tool_use blocks)
// and user entries (tool_result blocks) matter here.
type entry struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	UUID      string `json:"uuid"`
	Timestamp string `json:"timestamp"`
	Message   struct {
		// Content is an array of blocks for tool-carrying entries but a
		// plain string for simple text messages; raw-decoded so the string
		// form doesn't fail the whole line.
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

// contentBlock is one element of a message content array. tool_use and
// tool_result blocks populate disjoint field subsets.
type contentBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`   // tool_use: the toolu_… ID claims adopt
	Name      string          `json:"name"` // tool_use: tool name
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"` // tool_result: back-reference
}

func (e *entry) time() time.Time {
	t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return time.Time{}
	}
	return t
}

// blocks decodes the content array, returning nil for the plain-string
// form (no tool activity there by definition).
func (e *entry) blocks() []contentBlock {
	var bs []contentBlock
	if len(e.Message.Content) == 0 || json.Unmarshal(e.Message.Content, &bs) != nil {
		return nil
	}
	return bs
}

// targetKeys is the priority order for picking a tool call's claimed
// object out of its input. Commands are targets too: for Bash the command
// line IS what the agent claims to have done to the world.
var targetKeys = []string{
	"file_path", "notebook_path", "path", "url", "command", "query", "pattern", "skill",
}

// operationAndTarget renders one tool_use block into the claim vocabulary
// of corroborate.Claim.Operation, plus the claimed target.
//
//	Bash                              -> Bash(git push origin main)
//	Write                             -> Write
//	mcp__github__create_pull_request  -> mcp:github:create_pull_request
func operationAndTarget(b contentBlock) (op, target string) {
	var input map[string]any
	_ = json.Unmarshal(b.Input, &input) // absent/odd input just means no target
	for _, k := range targetKeys {
		if v, ok := input[k].(string); ok && v != "" {
			target = v
			break
		}
	}

	switch {
	case b.Name == "Bash":
		cmd, _ := input["command"].(string)
		target = cmd
		return "Bash(" + corroborate.BashOperation(cmd) + ")", target
	case strings.HasPrefix(b.Name, "mcp__"):
		return "mcp:" + strings.ReplaceAll(strings.TrimPrefix(b.Name, "mcp__"), "__", ":"), target
	default:
		return b.Name, target
	}
}
