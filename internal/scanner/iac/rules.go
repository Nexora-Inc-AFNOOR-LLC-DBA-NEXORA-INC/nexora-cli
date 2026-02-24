package iac

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	"github.com/Nexora-NHI/nexora-cli/internal/redact"
)

var (
	reAWSAccessKeyID  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reAWSSecretKey    = regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*"?[A-Za-z0-9/+=]{40}"?`)
	reIAMAction       = regexp.MustCompile(`(?i)"Action"\s*:\s*(\[[\s\S]*?\]|"[^"]*")`)
	reIAMActionHCL    = regexp.MustCompile(`(?i)actions\s*=\s*\[([^\]]*)\]`)
	reIAMPrincipal    = regexp.MustCompile(`(?i)"Principal"\s*:\s*"(\*)"`)
	reIAMResource     = regexp.MustCompile(`(?i)"Resource"\s*:\s*"(\*)"`)
	reServiceWildcard = regexp.MustCompile(`"[a-z0-9]+:\*"`)
)

var serviceWildcards = []string{"iam:*", "sts:*", "s3:*", "ec2:*", "lambda:*", "kms:*"}

func CheckIAMWildcardAction(content []byte, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	text := string(content)
	lines := strings.Split(text, "\n")

	// Check line-by-line for single-line patterns
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentLine(trimmed) {
			continue
		}
		if matchesWildcardAction(trimmed) {
			f := finding.Finding{
				RuleID:      "NXR-IAC-001",
				Severity:    finding.SeverityCritical,
				Title:       "IAM wildcard action or service wildcard",
				Description: "IAM policy contains a wildcard action ('*') or service-level wildcard.",
				NHIContext:  "Wildcard actions grant machine identities unrestricted API access, violating least privilege.",
				FilePath:    filePath,
				LineStart:   i + 1,
				LineEnd:     i + 1,
				Evidence:    fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(line)),
				Fix:         "Replace wildcard actions with the explicit set of required IAM actions.",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	// Also check multi-line HCL actions block: actions = [\n  "*"\n]
	if locs := reMultiLineHCLWildcard.FindAllStringIndex(text, -1); len(locs) > 0 {
		for _, loc := range locs {
			lineNum := strings.Count(text[:loc[0]], "\n") + 1
			// Avoid duplicating a finding already caught line-by-line
			alreadyCaught := false
			for _, existing := range findings {
				if existing.LineStart == lineNum {
					alreadyCaught = true
					break
				}
			}
			if alreadyCaught {
				continue
			}
			f := finding.Finding{
				RuleID:      "NXR-IAC-001",
				Severity:    finding.SeverityCritical,
				Title:       "IAM wildcard action or service wildcard",
				Description: "IAM policy contains a multi-line wildcard action block.",
				NHIContext:  "Wildcard actions grant machine identities unrestricted API access, violating least privilege.",
				FilePath:    filePath,
				LineStart:   lineNum,
				LineEnd:     lineNum,
				Evidence:    fmt.Sprintf("multi-line actions = [\"*\"] at line %d", lineNum),
				Fix:         "Replace wildcard actions with the explicit set of required IAM actions.",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func CheckHardcodedCredentials(content []byte, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	text := string(content)
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		if reAWSAccessKeyID.MatchString(line) {
			redacted := redact.String(line)
			f := finding.Finding{
				RuleID:      "NXR-IAC-002",
				Severity:    finding.SeverityCritical,
				Title:       "Hardcoded AWS Access Key ID in IaC",
				Description: "An AWS Access Key ID (AKIA...) is hardcoded in IaC source.",
				NHIContext:  "Hardcoded credentials in IaC are committed to version control and create persistent breach paths.",
				FilePath:    filePath,
				LineStart:   i + 1,
				LineEnd:     i + 1,
				Evidence:    strings.TrimSpace(redacted),
				Fix:         "Replace with IAM roles, instance profiles, or OIDC federation. Rotate the exposed key immediately.",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
		if reAWSSecretKey.MatchString(line) {
			f := finding.Finding{
				RuleID:      "NXR-IAC-002",
				Severity:    finding.SeverityCritical,
				Title:       "Hardcoded AWS Secret Access Key in IaC",
				Description: "An AWS secret access key assignment is hardcoded in IaC source.",
				NHIContext:  "Hardcoded credentials in IaC are committed to version control and create persistent breach paths.",
				FilePath:    filePath,
				LineStart:   i + 1,
				LineEnd:     i + 1,
				Evidence:    fmt.Sprintf("aws_secret_access_key assignment at line %d [REDACTED:AWS_SECRET_KEY]", i+1),
				Fix:         "Replace with IAM roles, instance profiles, or OIDC federation. Rotate the exposed key immediately.",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func CheckIAMTrustPolicyTooBroad(content []byte, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	text := string(content)
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		if isCommentLine(strings.TrimSpace(line)) {
			continue
		}
		if reIAMPrincipal.MatchString(line) {
			f := finding.Finding{
				RuleID:      "NXR-IAC-003",
				Severity:    finding.SeverityHigh,
				Title:       "IAM trust policy too broad — wildcard principal",
				Description: "IAM trust policy uses Principal: '*' without conditions.",
				NHIContext:  "A wildcard principal allows any AWS entity to assume this role, enabling privilege escalation.",
				FilePath:    filePath,
				LineStart:   i + 1,
				LineEnd:     i + 1,
				Evidence:    fmt.Sprintf("Principal: * at line %d", i+1),
				Fix:         "Restrict Principal to specific AWS accounts, roles, or services. Add Condition constraints.",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"},
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func CheckResourceWildcardWithBroadActions(content []byte, filePath string) ([]finding.Finding, error) {
	var findings []finding.Finding
	text := string(content)

	hasResourceWildcard := reIAMResource.MatchString(text)
	if !hasResourceWildcard {
		return findings, nil
	}

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if reIAMResource.MatchString(line) {
			if hasServiceWildcardNearby(text, i) {
				f := finding.Finding{
					RuleID:      "NXR-IAC-004",
					Severity:    finding.SeverityHigh,
					Title:       "Resource '*' with data-plane service wildcards",
					Description: "IAM policy combines Resource: '*' with service-level wildcard actions.",
					NHIContext:  "Unrestricted resource scope with broad actions grants machine identities access to all resources of that type.",
					FilePath:    filePath,
					LineStart:   i + 1,
					LineEnd:     i + 1,
					Evidence:    fmt.Sprintf("Resource: * with service wildcard actions at line %d", i+1),
					Fix:         "Scope Resource to specific ARNs and replace wildcard actions with explicit permissions.",
					References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"},
				}
				f.ComputeFingerprint()
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

var reHCLActionWildcard = regexp.MustCompile(`(?i)\bAction\s*=\s*"\*"`)
var reMultiLineHCLWildcard = regexp.MustCompile(`(?i)actions\s*=\s*\[[^\]]*"\*"[^\]]*\]`)

func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*")
}

func matchesWildcardAction(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, `"action": "*"`) ||
		strings.Contains(lower, `"action":["*"]`) ||
		strings.Contains(lower, `"action": ["*"]`) {
		return true
	}
	if reHCLActionWildcard.MatchString(line) {
		return true
	}
	for _, sw := range serviceWildcards {
		if strings.Contains(lower, sw) {
			return true
		}
	}
	if reServiceWildcard.MatchString(line) {
		return true
	}
	if reIAMActionHCL.MatchString(line) {
		m := reIAMActionHCL.FindStringSubmatch(line)
		if len(m) > 1 && strings.Contains(m[1], `"*"`) {
			return true
		}
	}
	return false
}

func hasServiceWildcardNearby(text string, lineIdx int) bool {
	lines := strings.Split(text, "\n")
	start := lineIdx - 10
	if start < 0 {
		start = 0
	}
	end := lineIdx + 10
	if end > len(lines) {
		end = len(lines)
	}
	window := strings.Join(lines[start:end], "\n")
	lower := strings.ToLower(window)
	for _, sw := range serviceWildcards {
		if strings.Contains(lower, sw) {
			return true
		}
	}
	return reServiceWildcard.MatchString(window)
}
