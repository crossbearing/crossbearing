// Package bedrock ingests AWS Bedrock model-invocation logs into the
// corroborate claim vocabulary: every executed tool call an agent made
// through Bedrock (Converse / InvokeModel with tool use) becomes a
// claim-side corroborate.Claim, and each model-caller session becomes a
// corroborate.Session.
//
// Bedrock model-invocation logging is the CLAIM side, not the record side.
// It captures what the agent asked the model to do — the toolUse blocks the
// model emitted and the toolResult blocks the agent submitted back — which
// is the agent's own account of its actions, exactly what the join
// corroborates against CloudTrail / Kubernetes audit / the other record
// streams. It is AWS-native and in-account, so a customer running agents on
// Bedrock gets a durable claim stream without instrumenting anything: the
// claim layer is consumed, never built. CloudTrail logs the same
// InvokeModel/Converse calls but redacts the bodies, so it carries no tool
// name or arguments and cannot stand in for this stream.
//
// Input is what model-invocation logging delivers: a JSON array or
// newline-delimited stream of ModelInvocationLog records, exported from the
// CloudWatch Logs group or the S3 bucket the customer configured (gzip is
// detected and decompressed). The record schema is declared locally — the
// lean-go.sum product property means no AWS SDK here; this ingester reads
// exported JSON over an io.Reader, needs a handful of fields, and never
// calls Bedrock (read-only: the engine consumes the claim layer, it does
// not invoke models).
//
// Only tool calls that returned a result count as claims: a toolUse the
// model emitted but for which the agent never submitted a toolResult was
// interrupted or denied before running, so the agent never did it. Errored
// results still count — a tool that failed still executed and may have
// touched infrastructure before failing.
package bedrock

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// invocationLog is the slice of a Bedrock ModelInvocationLog record this
// ingester reads (schemaType "ModelInvocationLog"). The request and
// response bodies are kept raw — their inner shape is provider-native for
// InvokeModel (Anthropic messages: type/id/name/input, tool_use/tool_result)
// and normalized for Converse (toolUse/toolResult blocks) — so both are
// parsed by the shape-tolerant body type below.
type invocationLog struct {
	SchemaType string    `json:"schemaType"`
	Timestamp  time.Time `json:"timestamp"`
	AccountID  string    `json:"accountId"`
	Region     string    `json:"region"`
	RequestID  string    `json:"requestId"`
	Operation  string    `json:"operation"` // Converse | ConverseStream | InvokeModel | …
	ModelID    string    `json:"modelId"`
	Identity   struct {
		ARN string `json:"arn"`
	} `json:"identity"`
	// RequestMetadata carries caller-supplied key/values when the client set
	// them; a session key here is the strongest per-agent grouping. Bedrock
	// does not enforce it, so it may be empty.
	RequestMetadata map[string]string `json:"requestMetadata"`
	Input           struct {
		InputBodyJSON json.RawMessage `json:"inputBodyJson"`
	} `json:"input"`
	Output struct {
		OutputBodyJSON json.RawMessage `json:"outputBodyJson"`
	} `json:"output"`
}

// toolCall is one tool the model asked to invoke: the name/args/id triple,
// the same shape claudecode reads from a transcript tool_use block.
type toolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// body parses either request or response body in both shapes Bedrock logs:
//
//	native Anthropic (InvokeModel): top-level "content" (assistant output) and
//	  "messages[].content" (prior turns) with {type,id,name,input} tool_use and
//	  {type,tool_use_id} tool_result blocks.
//	Converse: "output.message.content" and "messages[].content" with
//	  {toolUse:{toolUseId,name,input}} and {toolResult:{toolUseId,status}} blocks.
//
// A given block populates one shape's fields; the other stays zero, so the
// unified contentBlock decodes both without a branch on operation+modelId.
type body struct {
	Content  blockList `json:"content"` // native: assistant output blocks
	Messages []struct {
		Content blockList `json:"content"`
	} `json:"messages"` // request: prior-turn blocks (carry tool_result)
	Output *struct {
		Message struct {
			Content blockList `json:"content"`
		} `json:"message"`
	} `json:"output"` // Converse: response message blocks
}

// blockList tolerates both spellings of message content the Anthropic API
// accepts: a plain string (a turn with no tool blocks — the common first
// user message) or an array of blocks. Live validation caught the strict
// form poisoning a whole request body: one string-content turn made the
// body unmarshal fail, hiding the tool_result carried by a sibling turn.
type blockList []contentBlock

func (b *blockList) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] == '"' || string(raw) == "null" {
		*b = nil
		return nil
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return err
	}
	*b = blocks
	return nil
}

type contentBlock struct {
	// native Anthropic shape
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"` // native tool_result back-reference
	// Converse shape
	ToolUse    *converseToolUse    `json:"toolUse"`
	ToolResult *converseToolResult `json:"toolResult"`
}

type converseToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

type converseToolResult struct {
	ToolUseID string `json:"toolUseId"`
	Status    string `json:"status"` // success | error — errored still counts as executed
}

// toolActivity returns every tool the model asked to call (across the
// request and response bodies) and the IDs of every tool whose result the
// agent submitted back. Collecting from both bodies makes a single captured
// record self-sufficient when the export window clips the turn boundary: a
// follow-up request echoes the prior tool_use and carries its tool_result.
func (l *invocationLog) toolActivity() (uses []toolCall, executed []string) {
	u1, r1 := scanBody(l.Output.OutputBodyJSON)
	u2, r2 := scanBody(l.Input.InputBodyJSON)
	return append(u1, u2...), append(r1, r2...)
}

// scanBody decodes one body and walks every content block in it (native
// top-level, Converse output, and request-history messages), returning the
// tool_use calls and the tool_result IDs it carries.
func scanBody(raw json.RawMessage) (uses []toolCall, results []string) {
	raw = unquoteIfString(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var b body
	if json.Unmarshal(raw, &b) != nil {
		return nil, nil
	}
	scan := func(blocks blockList) {
		for _, blk := range blocks {
			switch {
			case blk.ToolUse != nil && blk.ToolUse.ToolUseID != "":
				uses = append(uses, toolCall{ID: blk.ToolUse.ToolUseID, Name: blk.ToolUse.Name, Input: blk.ToolUse.Input})
			case blk.Type == "tool_use" && blk.ID != "":
				uses = append(uses, toolCall{ID: blk.ID, Name: blk.Name, Input: blk.Input})
			case blk.ToolResult != nil && blk.ToolResult.ToolUseID != "":
				results = append(results, blk.ToolResult.ToolUseID)
			case blk.Type == "tool_result" && blk.ToolUseID != "":
				results = append(results, blk.ToolUseID)
			}
		}
	}
	scan(b.Content)
	if b.Output != nil {
		scan(b.Output.Message.Content)
	}
	for _, m := range b.Messages {
		scan(m.Content)
	}
	return uses, results
}

// unquoteIfString unwraps a body that was logged as a JSON string rather
// than an embedded object (some CloudWatch Logs exports stringify
// inputBodyJson/outputBodyJson). A leading quote means it's the string form;
// decode it back to the underlying JSON bytes.
func unquoteIfString(raw json.RawMessage) json.RawMessage {
	t := bytes.TrimSpace(raw)
	if len(t) > 0 && t[0] == '"' {
		var s string
		if json.Unmarshal(t, &s) == nil {
			return json.RawMessage(s)
		}
	}
	return raw
}

// targetKeys is the priority order for picking a tool call's claimed object
// out of its input, matching the claudecode convention so reports read the
// same across claim streams. A command is a target too: for a shell tool the
// command line is what the agent claims to have done to the world.
var targetKeys = []string{
	"command", "file_path", "path", "url", "query", "manifest", "name",
}

// operationAndTarget renders one tool call into the claim vocabulary of
// corroborate.Claim.Operation, plus the claimed target. A tool carrying a
// shell command becomes a Bash(…) claim so it rides the existing CLI
// translators (kubectl/aws/gh → record vocabulary) with no new mapping; any
// other tool keeps its own name and is corroborable once an attested
// operation-map seed wires it to a record stream.
//
// Shell detection is by the presence of a non-empty "command" string input,
// not a fixed tool name (Bedrock agents name their shell tool variably). A
// non-shell tool that happens to reuse a "command" input field would be
// rendered as Bash(…); the CLI translators then fail closed on anything that
// is not a recognized aws/kubectl/gh command, so the worst case is a claim
// that finds no record, never a wrong corroboration.
//
//	{name:"shell",  input:{command:"kubectl get pods"}}  -> Bash(kubectl get pods)
//	{name:"mcp__github__merge_pull_request"}             -> mcp:github:merge_pull_request
//	{name:"k8s_apply", input:{manifest:"…"}}             -> k8s_apply
func operationAndTarget(tc toolCall) (op, target string) {
	var input map[string]any
	_ = json.Unmarshal(tc.Input, &input) // absent/odd input just means no target
	for _, k := range targetKeys {
		if v, ok := input[k].(string); ok && v != "" {
			target = v
			break
		}
	}

	if cmd, ok := input["command"].(string); ok && cmd != "" {
		return "Bash(" + truncateCommand(cmd) + ")", cmd
	}
	// MCP tools are named mcp__<server>__<tool> by the agent runtime; normalize
	// to the mcp:<server>:<tool> claim vocabulary (same form claudecode emits)
	// so an attested seed map — e.g. MCPGitHubOperationMap — can wire them to a
	// record stream.
	if strings.HasPrefix(tc.Name, "mcp__") {
		return "mcp:" + strings.ReplaceAll(strings.TrimPrefix(tc.Name, "mcp__"), "__", ":"), target
	}
	if tc.Name == "" {
		return "tool", target
	}
	return tc.Name, target
}

// truncateCommand keeps the operation readable in reports: first line only,
// capped — the full command stays in Claim.Target.
func truncateCommand(cmd string) string {
	if i := strings.IndexByte(cmd, '\n'); i >= 0 {
		cmd = cmd[:i]
	}
	const max = 100
	if len(cmd) > max {
		return cmd[:max] + "…"
	}
	return cmd
}
