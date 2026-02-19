package k8s

import (
	"fmt"
	"strings"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"gopkg.in/yaml.v3"
)

func CheckClusterAdminBinding(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	root := docRoot(doc)
	if root == nil {
		return findings, nil
	}

	kind := scalarValue(root, "kind")
	if kind != "ClusterRoleBinding" {
		return findings, nil
	}

	roleRef := mappingValue(root, "roleRef")
	if roleRef == nil || scalarValue(roleRef, "name") != "cluster-admin" {
		return findings, nil
	}

	subjectsNode := mappingValue(root, "subjects")
	if subjectsNode == nil || subjectsNode.Kind != yaml.SequenceNode {
		return findings, nil
	}

	for _, subj := range subjectsNode.Content {
		if scalarValue(subj, "kind") == "ServiceAccount" {
			name := scalarValue(subj, "name")
			ns := scalarValue(subj, "namespace")
			f := finding.Finding{
				RuleID:      "NXR-K8S-001",
				Severity:    finding.SeverityCritical,
				Title:       "ServiceAccount bound to cluster-admin",
				Description: fmt.Sprintf("ServiceAccount %q in namespace %q is bound to cluster-admin.", name, ns),
				NHIContext:  "cluster-admin grants unrestricted API access; any workload using this SA has full cluster control.",
				FilePath:    filePath,
				LineStart:   subj.Line,
				LineEnd:     subj.Line,
				Evidence:    fmt.Sprintf("subject: %s/%s, roleRef: cluster-admin", ns, name),
				Fix:         "Replace cluster-admin binding with a least-privilege Role and RoleBinding scoped to the required namespace.",
				References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func CheckAutomountServiceAccountToken(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	root := docRoot(doc)
	if root == nil {
		return findings, nil
	}

	kind := scalarValue(root, "kind")
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
	case "ServiceAccount":
	default:
		return findings, nil
	}

	checkNode := root
	if kind != "Pod" && kind != "ServiceAccount" {
		spec := mappingValue(root, "spec")
		if spec != nil {
			template := mappingValue(spec, "template")
			if template != nil {
				podSpec := mappingValue(template, "spec")
				if podSpec != nil {
					checkNode = podSpec
				}
			}
		}
	} else if kind == "Pod" {
		spec := mappingValue(root, "spec")
		if spec != nil {
			checkNode = spec
		}
	}

	automount := mappingValue(checkNode, "automountServiceAccountToken")
	if automount != nil && automount.Value == "false" {
		return findings, nil
	}

	lineNum := 0
	if automount != nil {
		lineNum = automount.Line
	} else if checkNode != nil {
		lineNum = checkNode.Line
	}

	name := scalarValue(mappingValue(root, "metadata"), "name")
	f := finding.Finding{
		RuleID:      "NXR-K8S-002",
		Severity:    finding.SeverityInfo,
		Title:       "ServiceAccount token automount not explicitly disabled",
		Description: fmt.Sprintf("%s %q does not explicitly set automountServiceAccountToken: false.", kind, name),
		NHIContext:  "Automatically mounted tokens grant API access to any process in the pod; disable if not needed.",
		FilePath:    filePath,
		LineStart:   lineNum,
		LineEnd:     lineNum,
		Evidence:    fmt.Sprintf("kind: %s, name: %s", kind, name),
		Fix:         "Set automountServiceAccountToken: false on the PodSpec or ServiceAccount where API access is not required.",
		References:  []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting"},
	}
	f.ComputeFingerprint()
	findings = append(findings, f)
	return findings, nil
}

func CheckDefaultServiceAccount(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	root := docRoot(doc)
	if root == nil {
		return findings, nil
	}

	kind := scalarValue(root, "kind")
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
	default:
		return findings, nil
	}

	meta := mappingValue(root, "metadata")
	ns := ""
	if meta != nil {
		ns = scalarValue(meta, "namespace")
	}
	if strings.HasPrefix(ns, "kube-") {
		return findings, nil
	}

	podSpec := resolvePodSpec(root, kind)
	if podSpec == nil {
		return findings, nil
	}

	saNode := mappingValue(podSpec, "serviceAccountName")
	if saNode != nil && saNode.Value != "" && saNode.Value != "default" {
		return findings, nil
	}

	name := ""
	if meta != nil {
		name = scalarValue(meta, "name")
	}
	lineNum := 0
	if saNode != nil {
		lineNum = saNode.Line
	} else if podSpec != nil {
		lineNum = podSpec.Line
	}

	f := finding.Finding{
		RuleID:      "NXR-K8S-003",
		Severity:    finding.SeverityLow,
		Title:       "Default ServiceAccount used in non-system namespace",
		Description: fmt.Sprintf("%s %q uses the default ServiceAccount.", kind, name),
		NHIContext:  "The default ServiceAccount may accumulate permissions over time; dedicated SAs enforce least privilege.",
		FilePath:    filePath,
		LineStart:   lineNum,
		LineEnd:     lineNum,
		Evidence:    fmt.Sprintf("kind: %s, name: %s, serviceAccountName: default", kind, name),
		Fix:         "Create and reference a dedicated ServiceAccount per workload.",
		References:  []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"},
	}
	f.ComputeFingerprint()
	findings = append(findings, f)
	return findings, nil
}

func CheckWildcardRBACVerbs(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	root := docRoot(doc)
	if root == nil {
		return findings, nil
	}

	kind := scalarValue(root, "kind")
	if kind != "Role" && kind != "ClusterRole" {
		return findings, nil
	}

	rulesNode := mappingValue(root, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		return findings, nil
	}

	for _, rule := range rulesNode.Content {
		verbsNode := mappingValue(rule, "verbs")
		resourcesNode := mappingValue(rule, "resources")
		if verbsNode == nil || resourcesNode == nil {
			continue
		}
		if !seqContains(verbsNode, "*") {
			continue
		}
		if !seqContains(resourcesNode, "secrets") && !seqContains(resourcesNode, "*") {
			continue
		}
		f := finding.Finding{
			RuleID:      "NXR-K8S-004",
			Severity:    finding.SeverityHigh,
			Title:       "Wildcard RBAC verbs on sensitive resources",
			Description: fmt.Sprintf("%s grants wildcard verbs on secrets or all resources.", kind),
			NHIContext:  "Wildcard verbs on secrets allow any bound identity to read, modify, or delete all secrets.",
			FilePath:    filePath,
			LineStart:   rule.Line,
			LineEnd:     rule.Line,
			Evidence:    fmt.Sprintf("verbs: [*], resources: %s", seqValues(resourcesNode)),
			Fix:         "Replace wildcard verbs and resources with explicit minimal permissions.",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"},
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

func CheckProjectedTokenExpiry(doc *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	root := docRoot(doc)
	if root == nil {
		return findings, nil
	}

	kind := scalarValue(root, "kind")
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
	default:
		return findings, nil
	}

	podSpec := resolvePodSpec(root, kind)
	if podSpec == nil {
		return findings, nil
	}

	volumesNode := mappingValue(podSpec, "volumes")
	if volumesNode == nil || volumesNode.Kind != yaml.SequenceNode {
		return findings, nil
	}

	for _, vol := range volumesNode.Content {
		projected := mappingValue(vol, "projected")
		if projected == nil {
			continue
		}
		sources := mappingValue(projected, "sources")
		if sources == nil || sources.Kind != yaml.SequenceNode {
			continue
		}
		for _, src := range sources.Content {
			satNode := mappingValue(src, "serviceAccountToken")
			if satNode == nil {
				continue
			}
			expiryNode := mappingValue(satNode, "expirationSeconds")
			if expiryNode == nil {
				continue
			}
			var expiry int
			fmt.Sscanf(expiryNode.Value, "%d", &expiry)
			if expiry > 86400 {
				f := finding.Finding{
					RuleID:      "NXR-K8S-005",
					Severity:    finding.SeverityLow,
					Title:       "Projected ServiceAccountToken expirationSeconds too long",
					Description: fmt.Sprintf("Projected token has expirationSeconds=%d (>86400).", expiry),
					NHIContext:  "Long-lived projected tokens extend the window of credential misuse if stolen.",
					FilePath:    filePath,
					LineStart:   expiryNode.Line,
					LineEnd:     expiryNode.Line,
					Evidence:    fmt.Sprintf("expirationSeconds: %d", expiry),
					Fix:         "Set expirationSeconds to 3600 or less where possible.",
					References:  []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection"},
				}
				f.ComputeFingerprint()
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

// --- helpers ---

func docRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	if doc.Kind == yaml.MappingNode {
		return doc
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node, key string) string {
	v := mappingValue(node, key)
	if v == nil {
		return ""
	}
	return v.Value
}

func seqContains(node *yaml.Node, val string) bool {
	if node == nil || node.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range node.Content {
		if item.Value == val {
			return true
		}
	}
	return false
}

func seqValues(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.SequenceNode {
		return ""
	}
	vals := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		vals = append(vals, item.Value)
	}
	return "[" + strings.Join(vals, ", ") + "]"
}

func resolvePodSpec(root *yaml.Node, kind string) *yaml.Node {
	if kind == "Pod" {
		return mappingValue(root, "spec")
	}
	if kind == "CronJob" {
		spec := mappingValue(root, "spec")
		if spec == nil {
			return nil
		}
		jobTemplate := mappingValue(spec, "jobTemplate")
		if jobTemplate == nil {
			return nil
		}
		tmplSpec := mappingValue(jobTemplate, "spec")
		if tmplSpec == nil {
			return nil
		}
		template := mappingValue(tmplSpec, "template")
		if template == nil {
			return nil
		}
		return mappingValue(template, "spec")
	}
	spec := mappingValue(root, "spec")
	if spec == nil {
		return nil
	}
	template := mappingValue(spec, "template")
	if template == nil {
		return nil
	}
	return mappingValue(template, "spec")
}
