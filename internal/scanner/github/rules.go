package github

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/redact"
)

var reCommitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var reUntrustedCtx = regexp.MustCompile(`github\.(event\.issue\.title|event\.issue\.body|event\.pull_request\.title|event\.pull_request\.body|event\.comment\.body|event\.review\.body|event\.review_comment\.body)`)

func CheckBroadPermissions(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding

	wfPerms := extractPermissionsNode(node)
	if wfPerms == nil {
		return findings, nil
	}

	broad := false
	if wfPerms.Kind == yaml.ScalarNode && wfPerms.Value == "write-all" {
		broad = true
	} else if wfPerms.Kind == yaml.MappingNode {
		for i := 1; i < len(wfPerms.Content); i += 2 {
			if strings.HasSuffix(wfPerms.Content[i].Value, "write") || wfPerms.Content[i].Value == "write-all" {
				broad = true
				break
			}
		}
	}

	if !broad {
		return findings, nil
	}

	jobsNode := mappingValue(node, "jobs")
	if jobsNode == nil {
		return findings, nil
	}

	missingJobPerms := false
	for i := 1; i < len(jobsNode.Content); i += 2 {
		jobBody := jobsNode.Content[i]
		if mappingValue(jobBody, "permissions") == nil {
			missingJobPerms = true
			break
		}
	}

	if !missingJobPerms {
		return findings, nil
	}

	f := finding.Finding{
		RuleID:      "NXR-GH-001",
		Severity:    finding.SeverityHigh,
		Title:       "Broad workflow-level write permissions without job scoping",
		Description: "Workflow sets broad write permissions but one or more jobs do not define job-level permissions.",
		NHIContext:  "Broad identity permissions allow machine identities to modify repo state beyond what they need.",
		FilePath:    filePath,
		LineStart:   wfPerms.Line,
		LineEnd:     wfPerms.Line,
		Evidence:    fmt.Sprintf("permissions: %s", nodeValueSummary(wfPerms)),
		Fix:         "Set workflow-level default: permissions: {} and add minimal job-level permissions per job.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"},
	}
	f.ComputeFingerprint()
	findings = append(findings, f)
	return findings, nil
}

func CheckUnpinnedActions(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	visitSteps(node, func(step *yaml.Node) {
		usesNode := mappingValue(step, "uses")
		if usesNode == nil {
			return
		}
		uses := usesNode.Value
		if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
			return
		}
		parts := strings.SplitN(uses, "@", 2)
		if len(parts) != 2 {
			return
		}
		ref := parts[1]
		if reCommitSHA.MatchString(ref) {
			return
		}
		f := finding.Finding{
			RuleID:      "NXR-GH-002",
			Severity:    finding.SeverityHigh,
			Title:       "Action not pinned to commit SHA",
			Description: fmt.Sprintf("Action %q uses ref %q which is not a full commit SHA.", parts[0], ref),
			NHIContext:  "Unpinned dependencies can be changed to exfiltrate machine credentials available to the job.",
			FilePath:    filePath,
			LineStart:   usesNode.Line,
			LineEnd:     usesNode.Line,
			Evidence:    fmt.Sprintf("uses: %s", uses),
			Fix:         "Pin the action to a full 40-character commit SHA.",
			References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"},
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	})
	return findings, nil
}

func CheckPRTMisuse(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding

	if !hasTrigger(node, "pull_request_target") {
		return findings, nil
	}

	visitSteps(node, func(step *yaml.Node) {
		usesNode := mappingValue(step, "uses")
		if usesNode == nil {
			return
		}
		if !strings.Contains(usesNode.Value, "actions/checkout") {
			return
		}
		withNode := mappingValue(step, "with")
		if withNode == nil {
			return
		}
		refNode := mappingValue(withNode, "ref")
		if refNode == nil {
			return
		}
		ref := refNode.Value
		if strings.Contains(ref, "head") || strings.Contains(ref, "pull_request") || strings.Contains(ref, "sha") {
			f := finding.Finding{
				RuleID:      "NXR-GH-003",
				Severity:    finding.SeverityCritical,
				Title:       "pull_request_target with PR-head checkout",
				Description: "Workflow uses pull_request_target trigger and checks out PR head code.",
				NHIContext:  "Untrusted PR code executed with elevated token/secret context can leak machine credentials.",
				FilePath:    filePath,
				LineStart:   refNode.Line,
				LineEnd:     refNode.Line,
				Evidence:    fmt.Sprintf("ref: %s", ref),
				Fix:         "Avoid checking out PR head code under pull_request_target. Use a separate workflow for untrusted code.",
				References:  []string{"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	})
	return findings, nil
}

func CheckHardcodedSecrets(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding

	checkKV := func(key, value string, line int, context string) {
		if strings.HasPrefix(value, "${{") {
			return
		}
		if !redact.HasSecret(value) {
			return
		}
		redacted := redact.String(value)
		f := finding.Finding{
			RuleID:      "NXR-GH-004",
			Severity:    finding.SeverityCritical,
			Title:       "Hardcoded credential in workflow " + context,
			Description: fmt.Sprintf("Workflow %s key %q contains a hardcoded credential.", context, key),
			NHIContext:  "Hardcoded machine credentials become persistent breach paths via repo history and logs.",
			FilePath:    filePath,
			LineStart:   line,
			LineEnd:     line,
			Evidence:    fmt.Sprintf("%s: %s", key, redacted),
			Fix:         "Move to GitHub Secrets and reference via ${{ secrets.NAME }}.",
			References:  []string{"https://docs.github.com/en/actions/security-guides/encrypted-secrets"},
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}

	visitEnvValues(node, func(key, value string, line int) {
		checkKV(key, value, line, "env")
	})
	visitWithValues(node, func(key, value string, line int) {
		checkKV(key, value, line, "with")
	})
	return findings, nil
}

func CheckSelfHostedRunner(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	jobsNode := mappingValue(node, "jobs")
	if jobsNode == nil {
		return findings, nil
	}
	for i := 1; i < len(jobsNode.Content); i += 2 {
		jobBody := jobsNode.Content[i]
		runsOn := mappingValue(jobBody, "runs-on")
		if runsOn == nil {
			continue
		}
		isSelfHostedOnly := false
		if runsOn.Kind == yaml.ScalarNode && runsOn.Value == "self-hosted" {
			isSelfHostedOnly = true
		} else if runsOn.Kind == yaml.SequenceNode {
			if len(runsOn.Content) == 1 && runsOn.Content[0].Value == "self-hosted" {
				isSelfHostedOnly = true
			}
		}
		if !isSelfHostedOnly {
			continue
		}
		f := finding.Finding{
			RuleID:      "NXR-GH-005",
			Severity:    finding.SeverityMedium,
			Title:       "Self-hosted runner without restriction labels",
			Description: "Job uses bare 'self-hosted' runner without additional targeting labels.",
			NHIContext:  "Persistent runners increase credential persistence risk across runs.",
			FilePath:    filePath,
			LineStart:   runsOn.Line,
			LineEnd:     runsOn.Line,
			Evidence:    fmt.Sprintf("runs-on: %s", nodeValueSummary(runsOn)),
			Fix:         "Add specific labels or runner group targeting; prefer ephemeral runners.",
			References:  []string{"https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners"},
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

func CheckTokenExposurePRT(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	if !hasTrigger(node, "pull_request_target") {
		return findings, nil
	}
	raw, _ := yaml.Marshal(node)
	content := string(raw)
	if strings.Contains(content, "github.token") || strings.Contains(content, "GITHUB_TOKEN") {
		f := finding.Finding{
			RuleID:      "NXR-GH-006",
			Severity:    finding.SeverityHigh,
			Title:       "Token exposure risk in pull_request_target",
			Description: "Workflow uses pull_request_target and references github.token or GITHUB_TOKEN.",
			NHIContext:  "Secrets and tokens are accessible in pull_request_target context with elevated permissions.",
			FilePath:    filePath,
			LineStart:   0,
			LineEnd:     0,
			Evidence:    "pull_request_target + GITHUB_TOKEN/github.token reference",
			Fix:         "Minimize permissions, avoid secret exposure, isolate untrusted workflows.",
			References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"},
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

func CheckUntrustedInputInRun(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	visitSteps(node, func(step *yaml.Node) {
		runNode := mappingValue(step, "run")
		if runNode == nil {
			return
		}
		if reUntrustedCtx.MatchString(runNode.Value) {
			match := reUntrustedCtx.FindString(runNode.Value)
			f := finding.Finding{
				RuleID:      "NXR-GH-007",
				Severity:    finding.SeverityMedium,
				Title:       "Untrusted GitHub event body/title used in run step",
				Description: "A run step references untrusted event context (issue/PR body or title).",
				NHIContext:  "Untrusted input in shell commands can lead to code injection and credential exfiltration.",
				FilePath:    filePath,
				LineStart:   runNode.Line,
				LineEnd:     runNode.Line,
				Evidence:    fmt.Sprintf("run references: %s", match),
				Fix:         "Treat as untrusted input; sanitize before shell use or pass via environment variable.",
				References:  []string{"https://securitylab.github.com/research/github-actions-untrusted-input/"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	})
	return findings, nil
}

func CheckScheduledWritePermissions(node *yaml.Node, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	if !hasTrigger(node, "schedule") {
		return findings, nil
	}
	wfPerms := extractPermissionsNode(node)
	if wfPerms == nil {
		return findings, nil
	}
	hasWrite := false
	if wfPerms.Kind == yaml.ScalarNode && wfPerms.Value == "write-all" {
		hasWrite = true
	} else if wfPerms.Kind == yaml.MappingNode {
		for i := 1; i < len(wfPerms.Content); i += 2 {
			v := wfPerms.Content[i].Value
			if v == "write" || v == "write-all" {
				k := wfPerms.Content[i-1].Value
				if k == "contents" || k == "packages" || k == "write-all" {
					hasWrite = true
					break
				}
			}
		}
	}
	if !hasWrite {
		return findings, nil
	}
	f := finding.Finding{
		RuleID:      "NXR-GH-008",
		Severity:    finding.SeverityMedium,
		Title:       "Scheduled workflow with write permissions",
		Description: "Workflow triggered by schedule has write permissions (contents or packages).",
		NHIContext:  "Scheduled jobs with write permissions run unattended with elevated machine identity scope.",
		FilePath:    filePath,
		LineStart:   wfPerms.Line,
		LineEnd:     wfPerms.Line,
		Evidence:    fmt.Sprintf("permissions: %s (schedule trigger)", nodeValueSummary(wfPerms)),
		Fix:         "Reduce scheduled job identity permissions to the minimum required.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/automatic-token-authentication"},
	}
	f.ComputeFingerprint()
	findings = append(findings, f)
	return findings, nil
}

// --- helpers ---

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil {
		return nil
	}
	n := node
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func extractPermissionsNode(doc *yaml.Node) *yaml.Node {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	return mappingValue(root, "permissions")
}

func hasTrigger(doc *yaml.Node, trigger string) bool {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	onNode := mappingValue(root, "on")
	if onNode == nil {
		return false
	}
	if onNode.Kind == yaml.ScalarNode {
		return onNode.Value == trigger
	}
	if onNode.Kind == yaml.SequenceNode {
		for _, item := range onNode.Content {
			if item.Value == trigger {
				return true
			}
		}
	}
	if onNode.Kind == yaml.MappingNode {
		for i := 0; i < len(onNode.Content); i += 2 {
			if onNode.Content[i].Value == trigger {
				return true
			}
		}
	}
	return false
}

func visitSteps(doc *yaml.Node, fn func(*yaml.Node)) {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	jobsNode := mappingValue(root, "jobs")
	if jobsNode == nil {
		return
	}
	for i := 1; i < len(jobsNode.Content); i += 2 {
		jobBody := jobsNode.Content[i]
		stepsNode := mappingValue(jobBody, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range stepsNode.Content {
			fn(step)
		}
	}
}

func visitEnvValues(doc *yaml.Node, fn func(key, value string, line int)) {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	visitEnvNode(mappingValue(root, "env"), fn)
	jobsNode := mappingValue(root, "jobs")
	if jobsNode == nil {
		return
	}
	for i := 1; i < len(jobsNode.Content); i += 2 {
		jobBody := jobsNode.Content[i]
		visitEnvNode(mappingValue(jobBody, "env"), fn)
		stepsNode := mappingValue(jobBody, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range stepsNode.Content {
			visitEnvNode(mappingValue(step, "env"), fn)
		}
	}
}

func visitEnvNode(envNode *yaml.Node, fn func(key, value string, line int)) {
	if envNode == nil || envNode.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(envNode.Content); i += 2 {
		fn(envNode.Content[i].Value, envNode.Content[i+1].Value, envNode.Content[i+1].Line)
	}
}

func visitWithValues(doc *yaml.Node, fn func(key, value string, line int)) {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	jobsNode := mappingValue(root, "jobs")
	if jobsNode == nil {
		return
	}
	for i := 1; i < len(jobsNode.Content); i += 2 {
		jobBody := jobsNode.Content[i]
		stepsNode := mappingValue(jobBody, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range stepsNode.Content {
			withNode := mappingValue(step, "with")
			if withNode == nil || withNode.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(withNode.Content); j += 2 {
				fn(withNode.Content[j].Value, withNode.Content[j+1].Value, withNode.Content[j+1].Line)
			}
		}
	}
}

func nodeValueSummary(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return fmt.Sprintf("<%s>", n.Tag)
}
