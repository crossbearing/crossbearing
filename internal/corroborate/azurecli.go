package corroborate

import "strings"

// AzRecordOps parses a shell command and returns the azure-activity
// record-vocabulary operations its `az` invocations would produce.
//
// Azure is cleaner than gcloud: an operationName is
// <Provider>/<resourceType>/<action>, the az command group maps to a
// provider/resourceType through an allowlist, and the verb maps to the
// action (create/update → write, delete → delete). Anything outside the
// allowlist or those verbs fails closed — same contract as the other
// translators.
func AzRecordOps(command string) []string {
	var ops []string
	for _, seg := range shellCommands(command) {
		if op, ok := azInvocation(seg); ok {
			ops = append(ops, op)
		}
	}
	return ops
}

// azResources maps an az command group to its ARM provider/resourceType.
var azResources = map[string]string{
	"vm":              "Microsoft.Compute/virtualMachines",
	"disk":            "Microsoft.Compute/disks",
	"group":           "Microsoft.Resources/subscriptions/resourceGroups",
	"storage account": "Microsoft.Storage/storageAccounts",
	"network vnet":    "Microsoft.Network/virtualNetworks",
	"network nsg":     "Microsoft.Network/networkSecurityGroups",
	"keyvault":        "Microsoft.KeyVault/vaults",
	"aks":             "Microsoft.ContainerService/managedClusters",
	"role assignment": "Microsoft.Authorization/roleAssignments",
	"identity":        "Microsoft.ManagedIdentity/userAssignedIdentities",
}

// azVerbs maps an az verb to the ARM operation action suffix.
var azVerbs = map[string]string{
	"create": "write",
	"update": "write",
	"delete": "delete",
}

// azValueFlags consume the next token when not in --flag=value form.
var azValueFlags = map[string]bool{
	"-g": true, "--resource-group": true, "-n": true, "--name": true,
	"-l": true, "--location": true, "-o": true, "--output": true,
	"--subscription": true, "--query": true,
}

func azInvocation(tokens []string) (string, bool) {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || !isCommand(tokens[i], "az") {
		return "", false
	}
	i++

	var bare []string
	for ; i < len(tokens) && len(bare) < 5; i++ {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if azValueFlags[t] && !strings.Contains(t, "=") {
				i++ // skip the flag's value so it can't pose as the verb
			}
			continue
		}
		bare = append(bare, t)
	}

	// The command group is the longest allowlisted prefix; the verb is the
	// bare token immediately after it.
	for n := min(3, len(bare)-1); n >= 1; n-- {
		provider, ok := azResources[strings.Join(bare[:n], " ")]
		if !ok {
			continue
		}
		if suffix := azVerbs[bare[n]]; suffix != "" {
			return "azure-activity:" + provider + "/" + suffix, true
		}
		return "", false
	}
	return "", false
}
