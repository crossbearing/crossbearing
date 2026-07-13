package corroborate

import (
	"reflect"
	"testing"
)

func TestGcloudRecordOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "storage bucket create",
			command: "gcloud storage buckets create gs://agent-out --project demo",
			want:    []string{"gcp-audit:storage.buckets.create"},
		},
		{
			name:    "iam service-account create maps to the RPC name",
			command: "gcloud iam service-accounts create deployer --display-name x",
			want:    []string{"gcp-audit:google.iam.admin.v1.CreateServiceAccount"},
		},
		{
			name:    "iam policy binding maps to SetIamPolicy",
			command: "gcloud projects add-iam-policy-binding demo --member user:x --role roles/owner",
			want:    []string{"gcp-audit:SetIamPolicy"},
		},
		{
			name:    "container cluster delete",
			command: "gcloud container clusters delete prod --zone us-central1-a --quiet",
			want:    []string{"gcp-audit:google.container.v1.ClusterManager.DeleteCluster"},
		},
		{
			name:    "env prefix and positional arg past the verb ignored",
			command: "CLOUDSDK_CORE_PROJECT=demo gcloud storage buckets delete gs://x",
			want:    []string{"gcp-audit:storage.buckets.delete"},
		},
		{
			name:    "unmapped command fails closed",
			command: "gcloud compute instances create vm1",
			want:    nil,
		},
		{
			name:    "read-only gcloud verb unmapped",
			command: "gcloud storage buckets list",
			want:    nil,
		},
		{
			name:    "gcloud not in command position",
			command: `echo "run gcloud storage buckets delete later"`,
			want:    nil,
		},
		{
			name:    "compound: create then add binding",
			command: "gcloud storage buckets create gs://x && gcloud projects add-iam-policy-binding demo --member user:y --role roles/viewer",
			want:    []string{"gcp-audit:storage.buckets.create", "gcp-audit:SetIamPolicy"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := GcloudRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GcloudRecordOps(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestAzRecordOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "vm create",
			command: "az vm create -g rg -n api --image UbuntuLTS",
			want:    []string{"azure-activity:Microsoft.Compute/virtualMachines/write"},
		},
		{
			name:    "vm delete",
			command: "az vm delete -g rg -n api --yes",
			want:    []string{"azure-activity:Microsoft.Compute/virtualMachines/delete"},
		},
		{
			name:    "two-token group: storage account create",
			command: "az storage account create -n agentsa -g rg -l eastus",
			want:    []string{"azure-activity:Microsoft.Storage/storageAccounts/write"},
		},
		{
			name:    "role assignment create",
			command: "az role assignment create --assignee x --role Contributor",
			want:    []string{"azure-activity:Microsoft.Authorization/roleAssignments/write"},
		},
		{
			name:    "group create (update maps to write too)",
			command: "az group create -n rg -l eastus",
			want:    []string{"azure-activity:Microsoft.Resources/subscriptions/resourceGroups/write"},
		},
		{
			name:    "value flag before verb cannot pose as the verb",
			command: "az vm --subscription sub-1 create -n api -g rg",
			want:    []string{"azure-activity:Microsoft.Compute/virtualMachines/write"},
		},
		{
			name:    "unmapped verb (show) fails closed",
			command: "az vm show -g rg -n api",
			want:    nil,
		},
		{
			name:    "unmapped group fails closed",
			command: "az cosmosdb create -g rg -n db",
			want:    nil,
		},
		{
			name:    "az not in command position",
			command: `git commit -m "use az vm create in the runbook"`,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AzRecordOps(tt.command); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AzRecordOps(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestDeriveOperationMap_CloudCLITranslators(t *testing.T) {
	t.Parallel()
	claims := []Claim{
		{Operation: "Bash(gcloud storage buckets create gs://x)", Target: "gcloud storage buckets create gs://x"},
		{Operation: "Bash(az vm create -g rg -n api)", Target: "az vm create -g rg -n api"},
	}
	m := DeriveOperationMap(claims)
	if got := m["gcloud storage buckets create gs://x"]; len(got) != 1 || got[0] != "gcp-audit:storage.buckets.create" {
		t.Errorf("gcloud entry = %v", got)
	}
	if got := m["az vm create -g rg -n api"]; len(got) != 1 || got[0] != "azure-activity:Microsoft.Compute/virtualMachines/write" {
		t.Errorf("az entry = %v", got)
	}
}
