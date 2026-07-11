package corroborate

import "strings"

// GcloudRecordOps parses a shell command and returns the gcp-audit
// record-vocabulary operations its `gcloud` invocations would produce.
//
// Unlike kubectl, gcloud verbs do NOT map algorithmically to GCP audit
// methodNames: the methodName is service-specific and irregular
// (compute uses "insert" where the CLI says "create"; some are
// fully-qualified RPC names like google.iam.admin.v1.CreateServiceAccount;
// some carry version prefixes). So this is an attested-only seed, fail
// closed on everything unmapped — a wrong mapping corroborates against the
// wrong record, which is worse than no mapping. The table grows from real
// partner audit logs where the exact methodName strings are observed; the
// entries here are the ones whose methodNames are stable and verified.
func GcloudRecordOps(command string) []string {
	var ops []string
	for _, seg := range shellSegments(command) {
		ops = append(ops, gcloudInvocation(seg)...)
	}
	return ops
}

// gcloudOps keys are the gcloud command path (group… verb), values the
// gcp-audit:<methodName> operations they produce. Attested-only.
var gcloudOps = map[string][]string{
	"storage buckets create":             {"gcp-audit:storage.buckets.create"},
	"storage buckets delete":             {"gcp-audit:storage.buckets.delete"},
	"storage buckets update":             {"gcp-audit:storage.buckets.update"},
	"iam service-accounts create":        {"gcp-audit:google.iam.admin.v1.CreateServiceAccount"},
	"iam service-accounts delete":        {"gcp-audit:google.iam.admin.v1.DeleteServiceAccount"},
	"projects add-iam-policy-binding":    {"gcp-audit:SetIamPolicy"},
	"projects remove-iam-policy-binding": {"gcp-audit:SetIamPolicy"},
	"container clusters create":          {"gcp-audit:google.container.v1.ClusterManager.CreateCluster"},
	"container clusters delete":          {"gcp-audit:google.container.v1.ClusterManager.DeleteCluster"},
}

func gcloudInvocation(tokens []string) []string {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || tokens[i] != "gcloud" {
		return nil
	}
	i++

	// Collect bare (non-flag) tokens: the command path is the leading run
	// of them; positional args trail and don't match an attested prefix.
	var bare []string
	for ; i < len(tokens) && len(bare) < 5; i++ {
		if strings.HasPrefix(tokens[i], "-") {
			continue
		}
		bare = append(bare, tokens[i])
	}

	// Longest attested prefix wins (keys are 2–3 tokens; positional args
	// past the verb are ignored).
	for n := min(4, len(bare)); n >= 2; n-- {
		if mapped, ok := gcloudOps[strings.Join(bare[:n], " ")]; ok {
			return mapped
		}
	}
	return nil
}
