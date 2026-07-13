package corroborate

import (
	"reflect"
	"testing"
)

// The commands below are verbatim from the agent transcript of the
// 2026-07-13 dev-eks run — the one that restarted three production
// workloads. Before shellCommands, every one of them translated to
// nothing: the audit log held three `patch` records the claim side could
// not account for, so the engine would have reported three unclaimed
// production changes that the agent had, in fact, plainly announced.
func TestShellCommands_RealAgentScripts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name: "kubectl via a path-assigned variable, the shape the agent actually wrote",
			command: "export PATH=\"/opt/homebrew/bin:/usr/bin\"\n" +
				"export AWS_PROFILE=stxkxs\n" +
				"K=/usr/local/bin/kubectl\n" +
				"$K -n monitoring rollout restart ds/alloy 2>&1",
			want: []string{"k8s-audit:patch:daemonsets"},
		},
		{
			name:    "rollout restart of a deployment",
			command: "K=/usr/local/bin/kubectl\n$K -n opencost rollout restart deploy/opencost 2>&1",
			want:    []string{"k8s-audit:patch:deployments"},
		},
		{
			name:    "rollout restart of a statefulset",
			command: "K=kubectl\n$K -n argocd rollout restart statefulset/argocd-application-controller",
			want:    []string{"k8s-audit:patch:statefulsets"},
		},
		{
			name:    "the secret read that preceded the credential pivot",
			command: "K=/usr/local/bin/kubectl\n$K -n argocd get secret argocd-initial-admin-secret -o json",
			want:    []string{"k8s-audit:get:secrets", "k8s-audit:list:secrets"},
		},
		{
			name:    "rollout status reads, it does not mutate",
			command: "K=kubectl\n$K -n monitoring rollout status ds/alloy --timeout=150s | tail -2",
			want:    []string{"k8s-audit:get:daemonsets", "k8s-audit:list:daemonsets"},
		},
		{
			name:    "braced reference",
			command: "K=kubectl\n${K} -n prod delete deployment/api",
			want:    []string{"k8s-audit:delete:deployments", "k8s-audit:deletecollection:deployments"},
		},
		{
			name:    "a variable holding flags word-splits, landing the CLI in command position",
			command: "K=\"kubectl --context dev-eks\"\n$K -n prod patch deploy/api",
			want:    []string{"k8s-audit:patch:deployments"},
		},
		{
			name:    "invoked by absolute path, no variable",
			command: "/usr/local/bin/kubectl -n prod patch deploy/api",
			want:    []string{"k8s-audit:patch:deployments"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := KubectlRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubectlRecordOps() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Resolution must not manufacture a translation. Each case below is a
// command we cannot confidently read, and inventing an operation for it
// would corroborate a claim against the wrong record — the one failure
// mode worse than translating nothing.
func TestShellCommands_FailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
	}{
		{"unassigned variable stays unresolved", "$KUBECTL -n prod delete deploy/api"},
		{"a variable assigned elsewhere is not guessed at", "$K delete deploy/api"},
		{"variable holding something else entirely", "K=echo\n$K kubectl delete deploy/api"},
		{"a lookalike binary is not kubectl", "mykubectl delete deploy/api"},
		{"kubectl plugins are their own binaries", "kubectl-argo-rollouts delete deploy/api"},
		{"the name only appears as an argument", "echo kubectl delete deploy/api"},
		{"quoted prose mentioning a command", "git commit -m 'run kubectl delete deploy/api next'"},
		{"a command-scoped assignment does not leak onward", "FOO=kubectl true\n$FOO delete deploy/api"},
		{"rollout without a resource", "kubectl rollout restart"},
		{"unknown rollout subcommand", "kubectl rollout frobnicate deploy/api"},
		{"file-based rollout stays unknowable", "kubectl rollout restart -f workloads.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := KubectlRecordOps(tt.command); len(got) != 0 {
				t.Errorf("KubectlRecordOps(%q) = %v, want nothing — it must fail closed", tt.command, got)
			}
		})
	}
}

// The indirections are not kubectl's alone; scripts reach every CLI this
// way, and each translator now resolves them through the same path.
func TestShellCommands_EveryCLI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		fn      func(string) []string
		command string
		want    []string
	}{
		{"aws by variable", AWSCLIRecordOps, "A=/usr/local/bin/aws\n$A sts get-caller-identity", []string{"sts:GetCallerIdentity"}},
		{"gh by absolute path", GHCLIRecordOps, "/opt/homebrew/bin/gh pr merge 99 --squash", []string{"github-audit:pull_request.merge"}},
		{"gcloud by variable", GcloudRecordOps, "G=gcloud\n$G storage buckets delete gs://b", []string{"gcp-audit:storage.buckets.delete"}},
		{"az by variable", AzRecordOps, "AZ=az\n$AZ group delete --name rg-1", []string{"azure-activity:Microsoft.Resources/subscriptions/resourceGroups/delete"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.fn(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
