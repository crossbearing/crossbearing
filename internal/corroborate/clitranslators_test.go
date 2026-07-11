package corroborate

import (
	"reflect"
	"strings"
	"testing"
)

func TestKubectlRecordOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "create with alias",
			command: "kubectl create deploy api --image=x",
			want:    []string{"k8s-audit:create:deployments"},
		},
		{
			name:    "delete TYPE/NAME form with namespace flag",
			command: "kubectl -n prod delete deployment/api",
			want:    []string{"k8s-audit:delete:deployments", "k8s-audit:deletecollection:deployments"},
		},
		{
			name:    "get maps to get and list",
			command: "kubectl get pods -n prod -o json",
			want:    []string{"k8s-audit:get:pods", "k8s-audit:list:pods"},
		},
		{
			name:    "apigroup suffix stripped",
			command: "kubectl describe deployments.apps api",
			want:    []string{"k8s-audit:get:deployments", "k8s-audit:list:deployments"},
		},
		{
			name:    "scale targets the scale subresource",
			command: "kubectl scale sts db --replicas=3",
			want:    []string{"k8s-audit:patch:statefulsets/scale", "k8s-audit:update:statefulsets/scale"},
		},
		{
			name:    "exec is a pods/exec create regardless of pod name",
			command: "kubectl exec -n prod api-7d9f -- /bin/sh -c id",
			want:    []string{"k8s-audit:create:pods/exec"},
		},
		{
			name:    "logs is pods/log",
			command: "kubectl logs api-7d9f -n prod --tail 50",
			want:    []string{"k8s-audit:get:pods/log"},
		},
		{
			name:    "apply is file-based: fail closed",
			command: "kubectl apply -f deploy.yaml",
			want:    nil,
		},
		{
			name:    "delete -f: fail closed",
			command: "kubectl delete -f stack.yaml",
			want:    nil,
		},
		{
			name:    "unknown resource: fail closed",
			command: "kubectl get widgets.example.io",
			want:    nil,
		},
		{
			name:    "kubectl not in command position",
			command: `echo "run kubectl delete pods later"`,
			want:    nil,
		},
		{
			name:    "compound with env prefix",
			command: "KUBECONFIG=/tmp/kc kubectl get ns && kubectl delete cm stale -n prod",
			want: []string{
				"k8s-audit:get:namespaces", "k8s-audit:list:namespaces",
				"k8s-audit:delete:configmaps", "k8s-audit:deletecollection:configmaps",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := KubectlRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubectlRecordOps(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestGHCLIRecordOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "git push",
			command: "git push origin main",
			want:    []string{"github-audit:git.push"},
		},
		{
			name:    "git push with -C and force flags",
			command: "git -C /repo push --force-with-lease origin work",
			want:    []string{"github-audit:git.push"},
		},
		{
			name:    "gh pr merge",
			command: "gh pr merge 42 --squash",
			want:    []string{"github-audit:pull_request.merge"},
		},
		{
			name:    "gh repo create",
			command: "gh repo create crossbearing/demo --private",
			want:    []string{"github-audit:repo.create"},
		},
		{
			name:    "compound: commit then push maps only the push",
			command: `git add -A && git commit -m "save" && git push origin main`,
			want:    []string{"github-audit:git.push"},
		},
		{
			name:    "unattested gh subcommand: fail closed",
			command: "gh pr view 42 && gh api repos/o/r",
			want:    nil,
		},
		{
			name:    "git pull is not a push",
			command: "git pull --rebase origin main",
			want:    nil,
		},
		{
			name:    "prose in quotes",
			command: `git commit -m "teach the agent to git push artifacts"`,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := GHCLIRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GHCLIRecordOps(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestDeriveOperationMap_AllTranslators(t *testing.T) {
	t.Parallel()
	claims := []Claim{
		{Operation: "Bash(kubectl delete deployment api -n prod)", Target: "kubectl delete deployment api -n prod"},
		{Operation: "Bash(git push origin main)", Target: "git push origin main"},
		{Operation: "Bash(aws sts get-caller-identity)", Target: "aws sts get-caller-identity"},
	}
	m := DeriveOperationMap(claims)
	if len(m) != 3 {
		t.Fatalf("map entries = %d, want 3: %v", len(m), m)
	}
	if got := m["Bash(kubectl delete deployment api -n prod)"]; got[0] != "k8s-audit:delete:deployments" {
		t.Errorf("kubectl entry = %v", got)
	}
	if got := m["Bash(git push origin main)"]; len(got) != 1 || got[0] != "github-audit:git.push" {
		t.Errorf("git push entry = %v", got)
	}
}

// FuzzCLIRecordOps holds all three translators panic-free and
// shape-correct over arbitrary shell text — claim targets are an
// untrusted stream.
func FuzzCLIRecordOps(f *testing.F) {
	f.Add("kubectl delete deployment/api -n prod && git push origin main")
	f.Add("gh pr merge 1 --squash; aws sts get-caller-identity")
	f.Add("kubectl exec pod -- sh -c 'kubectl get all'")
	f.Add("git -C")
	f.Add("kubectl scale --replicas")
	f.Add("gcloud storage buckets create gs://x && az vm delete -g rg -n api --yes")
	f.Add("az storage account create -n")
	f.Add("gcloud projects add-iam-policy-binding")
	f.Fuzz(func(t *testing.T, command string) {
		for _, translate := range cliTranslators {
			for _, op := range translate(command) {
				stream, rest, ok := strings.Cut(op, ":")
				if !ok || stream == "" || rest == "" {
					t.Fatalf("malformed op %q from %q", op, command)
				}
			}
		}
	})
}
