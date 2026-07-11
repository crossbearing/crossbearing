package corroborate

// MCPGitHubOperationMap seeds OperationMap entries for claims made through
// the GitHub MCP server (the claim vocabulary claudecode emits:
// "mcp:github:<tool>") against the org audit-log record vocabulary
// ("github-audit:<action>").
//
// Deliberately tiny and attested-only: a wrong entry corroborates a claim
// against the wrong record, which is worse than no entry (fail closed —
// an unmapped claim is simply not record-corroborable). The map grows
// empirically as design-partner audit logs show which MCP tools produce
// which audit actions.
func MCPGitHubOperationMap() map[string][]string {
	return map[string][]string{
		"mcp:github:create_repository":     {"github-audit:repo.create"},
		"mcp:github:merge_pull_request":    {"github-audit:pull_request.merge"},
		"mcp:github:create_branch":         {"github-audit:git.create_ref"},
		"mcp:github:delete_file":           {"github-audit:git.push"},
		"mcp:github:push_files":            {"github-audit:git.push"},
		"mcp:github:create_or_update_file": {"github-audit:git.push"},
	}
}

// MergeOperationMaps overlays maps left to right without clobbering:
// earlier entries win, so derived (claim-specific) vocabulary outranks
// static seeds.
func MergeOperationMaps(maps ...map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for _, m := range maps {
		for k, v := range m {
			if _, exists := out[k]; !exists {
				out[k] = v
			}
		}
	}
	return out
}
