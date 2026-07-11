package corroborate

import "strings"

// KubectlRecordOps parses a shell command and returns the k8s-audit
// record-vocabulary operations ("k8s-audit:create:deployments") its
// kubectl invocations would produce. The same conservatism as the aws
// translator, for the same reason: a wrong entry corroborates a claim
// against the wrong record, so anything not confidently translatable
// contributes nothing.
//
// Deliberately untranslatable, with rationale:
//   - `kubectl apply -f …` and anything file-based (-f/-k): the resources
//     live in the file, not the command line — unknowable from the claim.
//   - unknown resource aliases: the audit log speaks lowercase-plural
//     resource names; only aliases in the table below translate. A CRD or
//     exotic resource fails closed rather than guessing a pluralization.
func KubectlRecordOps(command string) []string {
	var ops []string
	for _, seg := range shellSegments(command) {
		ops = append(ops, kubectlInvocation(seg)...)
	}
	return ops
}

// kubectlValueFlags consume the next token.
var kubectlValueFlags = map[string]bool{
	"-n": true, "--namespace": true, "--context": true, "--kubeconfig": true,
	"--cluster": true, "-o": true, "--output": true, "-l": true, "--selector": true,
	"--field-selector": true, "--sort-by": true, "--template": true,
}

// kubectlVerbOps maps a kubectl verb to the audit verbs it may
// legitimately produce on the named resource. Multiple alternatives are
// the OperationMap's job to hold: `kubectl get pods` is a list when bare
// and a get when named, and the matcher accepts either.
var kubectlVerbOps = map[string][]string{
	"get":      {"get", "list"},
	"describe": {"get", "list"},
	"create":   {"create"},
	"delete":   {"delete", "deletecollection"},
	"patch":    {"patch"},
	"edit":     {"patch", "update"},
	"label":    {"patch"},
	"annotate": {"patch"},
	// scale acts on the scale subresource; the suffix is added below.
	"scale": {"patch", "update"},
}

// kubectlPodVerbs act on a pod subresource; the "resource" argument on
// the command line is a pod NAME, not a type, so the mapping is fixed.
var kubectlPodVerbs = map[string]string{
	"exec":         "k8s-audit:create:pods/exec",
	"logs":         "k8s-audit:get:pods/log",
	"port-forward": "k8s-audit:create:pods/portforward",
	"attach":       "k8s-audit:create:pods/attach",
	"run":          "k8s-audit:create:pods",
}

// kubectlResources is the allowlist of CLI spellings → audit-log resource
// names (lowercase plural). Fail closed on anything else.
var kubectlResources = map[string]string{
	"po": "pods", "pod": "pods", "pods": "pods",
	"deploy": "deployments", "deployment": "deployments", "deployments": "deployments",
	"svc": "services", "service": "services", "services": "services",
	"cm": "configmaps", "configmap": "configmaps", "configmaps": "configmaps",
	"secret": "secrets", "secrets": "secrets",
	"ns": "namespaces", "namespace": "namespaces", "namespaces": "namespaces",
	"no": "nodes", "node": "nodes", "nodes": "nodes",
	"ing": "ingresses", "ingress": "ingresses", "ingresses": "ingresses",
	"job": "jobs", "jobs": "jobs",
	"cj": "cronjobs", "cronjob": "cronjobs", "cronjobs": "cronjobs",
	"ds": "daemonsets", "daemonset": "daemonsets", "daemonsets": "daemonsets",
	"sts": "statefulsets", "statefulset": "statefulsets", "statefulsets": "statefulsets",
	"rs": "replicasets", "replicaset": "replicasets", "replicasets": "replicasets",
	"sa": "serviceaccounts", "serviceaccount": "serviceaccounts", "serviceaccounts": "serviceaccounts",
	"pvc": "persistentvolumeclaims", "persistentvolumeclaim": "persistentvolumeclaims", "persistentvolumeclaims": "persistentvolumeclaims",
	"pv": "persistentvolumes", "persistentvolume": "persistentvolumes", "persistentvolumes": "persistentvolumes",
	"role": "roles", "roles": "roles",
	"rolebinding": "rolebindings", "rolebindings": "rolebindings",
	"clusterrole": "clusterroles", "clusterroles": "clusterroles",
	"clusterrolebinding": "clusterrolebindings", "clusterrolebindings": "clusterrolebindings",
	"ep": "endpoints", "endpoint": "endpoints", "endpoints": "endpoints",
	"netpol": "networkpolicies", "networkpolicy": "networkpolicies", "networkpolicies": "networkpolicies",
	"hpa": "horizontalpodautoscalers", "horizontalpodautoscaler": "horizontalpodautoscalers", "horizontalpodautoscalers": "horizontalpodautoscalers",
	"crd": "customresourcedefinitions", "customresourcedefinition": "customresourcedefinitions", "customresourcedefinitions": "customresourcedefinitions",
	"event": "events", "events": "events", "ev": "events",
}

func kubectlInvocation(tokens []string) []string {
	i := 0
	for i < len(tokens) && (isEnvAssign(tokens[i]) || commandWrappers[tokens[i]]) {
		i++
	}
	if i >= len(tokens) || tokens[i] != "kubectl" {
		return nil
	}
	i++

	var bare []string
	for ; i < len(tokens); i++ {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			// File-based input makes the touched resources unknowable.
			if t == "-f" || t == "--filename" || t == "-k" || t == "--kustomize" || strings.HasPrefix(t, "--filename=") {
				return nil
			}
			if kubectlValueFlags[t] && !strings.Contains(t, "=") {
				i++
			}
			continue
		}
		bare = append(bare, t)
		if len(bare) == 2 {
			break
		}
	}
	if len(bare) == 0 {
		return nil
	}

	verb := bare[0]
	if op, ok := kubectlPodVerbs[verb]; ok {
		return []string{op}
	}
	auditVerbs, ok := kubectlVerbOps[verb]
	if !ok || len(bare) < 2 {
		return nil
	}

	// Resource token forms: TYPE, TYPE/NAME, TYPE.APIGROUP.
	res := bare[1]
	if j := strings.IndexByte(res, '/'); j >= 0 {
		res = res[:j]
	}
	if j := strings.IndexByte(res, '.'); j >= 0 {
		res = res[:j]
	}
	plural, ok := kubectlResources[strings.ToLower(res)]
	if !ok {
		return nil
	}

	ops := make([]string, 0, len(auditVerbs))
	suffix := ""
	if verb == "scale" {
		suffix = "/scale"
	}
	for _, v := range auditVerbs {
		ops = append(ops, "k8s-audit:"+v+":"+plural+suffix)
	}
	return ops
}
