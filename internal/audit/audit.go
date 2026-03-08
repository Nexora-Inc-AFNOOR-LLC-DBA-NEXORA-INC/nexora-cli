// Package audit provides credential lifecycle auditing via platform APIs.
// This is UNIQUE - file scanners cannot detect credential age, last use, or rotation status.
package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v60/github"
)

// CredentialAudit represents the result of auditing credentials
type CredentialAudit struct {
	Provider    string              `json:"provider"`
	Scope       string              `json:"scope"`
	AuditedAt   time.Time           `json:"audited_at"`
	Credentials []AuditedCredential `json:"credentials"`
	Summary     AuditSummary        `json:"summary"`
}

// AuditedCredential represents a single credential with lifecycle data
type AuditedCredential struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	CreatedAt   time.Time         `json:"created_at"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	LastRotated *time.Time        `json:"last_rotated,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	AgeInDays   int               `json:"age_days"`
	DormantDays int               `json:"dormant_days,omitempty"`
	Risk        RiskLevel         `json:"risk"`
	RiskReasons []string          `json:"risk_reasons"`
	Owner       string            `json:"owner,omitempty"`
	Scope       string            `json:"scope,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RiskLevel for credentials
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
)

// AuditSummary provides aggregate statistics
type AuditSummary struct {
	TotalCredentials  int `json:"total_credentials"`
	CriticalRisk      int `json:"critical_risk"`
	HighRisk          int `json:"high_risk"`
	MediumRisk        int `json:"medium_risk"`
	LowRisk           int `json:"low_risk"`
	StaleCount        int `json:"stale_count"`
	DormantCount      int `json:"dormant_count"`
	NeverRotatedCount int `json:"never_rotated_count"`
	ExpiringCount     int `json:"expiring_count"`
	ExpiredCount      int `json:"expired_count"`
}

// AuditThresholds for risk assessment
type AuditThresholds struct {
	MaxAgeDays        int
	MaxDormantDays    int
	MaxRotationDays   int
	ExpirationWarning int
}

// DefaultThresholds returns industry-standard thresholds
func DefaultThresholds() AuditThresholds {
	return AuditThresholds{
		MaxAgeDays:        90,
		MaxDormantDays:    30,
		MaxRotationDays:   90,
		ExpirationWarning: 7,
	}
}

// GitHubAuditor audits GitHub credentials
type GitHubAuditor struct {
	client     *github.Client
	thresholds AuditThresholds
}

// NewGitHubAuditor creates a new GitHub credential auditor
func NewGitHubAuditor(client *github.Client, thresholds AuditThresholds) *GitHubAuditor {
	return &GitHubAuditor{
		client:     client,
		thresholds: thresholds,
	}
}

// AuditOrg audits all credentials in a GitHub organization
func (a *GitHubAuditor) AuditOrg(ctx context.Context, org string) (*CredentialAudit, error) {
	audit := &CredentialAudit{
		Provider:  "github",
		Scope:     org,
		AuditedAt: time.Now(),
	}

	deployKeys, err := a.auditDeployKeys(ctx, org)
	if err == nil {
		audit.Credentials = append(audit.Credentials, deployKeys...)
	}

	secrets, err := a.auditOrgSecrets(ctx, org)
	if err == nil {
		audit.Credentials = append(audit.Credentials, secrets...)
	}

	apps, err := a.auditGitHubApps(ctx, org)
	if err == nil {
		audit.Credentials = append(audit.Credentials, apps...)
	}

	sort.Slice(audit.Credentials, func(i, j int) bool {
		return riskOrder(audit.Credentials[i].Risk) < riskOrder(audit.Credentials[j].Risk)
	})

	audit.Summary = a.calculateSummary(audit.Credentials)

	return audit, nil
}

func (a *GitHubAuditor) auditDeployKeys(ctx context.Context, org string) ([]AuditedCredential, error) {
	var credentials []AuditedCredential

	repos, _, err := a.client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		return nil, err
	}

	for _, repo := range repos {
		keys, _, err := a.client.Repositories.ListKeys(ctx, org, repo.GetName(), nil)
		if err != nil {
			continue
		}

		for _, key := range keys {
			cred := AuditedCredential{
				ID:        fmt.Sprintf("deploy-key-%d", key.GetID()),
				Name:      fmt.Sprintf("%s/%s: %s", org, repo.GetName(), key.GetTitle()),
				Type:      "deploy_key",
				CreatedAt: key.GetCreatedAt().Time,
				AgeInDays: int(time.Since(key.GetCreatedAt().Time).Hours() / 24),
				Metadata: map[string]string{
					"repo":      repo.GetFullName(),
					"read_only": fmt.Sprintf("%v", key.GetReadOnly()),
				},
			}

			if !key.GetReadOnly() {
				cred.Scope = "contents:write"
			} else {
				cred.Scope = "contents:read"
			}

			cred.Risk, cred.RiskReasons = a.assessCredentialRisk(&cred)
			credentials = append(credentials, cred)
		}
	}

	return credentials, nil
}

func (a *GitHubAuditor) auditOrgSecrets(ctx context.Context, org string) ([]AuditedCredential, error) {
	var credentials []AuditedCredential

	secrets, _, err := a.client.Actions.ListOrgSecrets(ctx, org, nil)
	if err != nil {
		return nil, err
	}

	for _, secret := range secrets.Secrets {
		lastRotated := secret.UpdatedAt.Time
		cred := AuditedCredential{
			ID:          fmt.Sprintf("secret-%s", secret.Name),
			Name:        secret.Name,
			Type:        "org_secret",
			CreatedAt:   secret.CreatedAt.Time,
			LastRotated: &lastRotated,
			AgeInDays:   int(time.Since(secret.CreatedAt.Time).Hours() / 24),
			Scope:       secret.Visibility,
			Metadata: map[string]string{
				"visibility": secret.Visibility,
			},
		}

		cred.Risk, cred.RiskReasons = a.assessCredentialRisk(&cred)

		if isHighValueSecretName(secret.Name) && cred.Risk != RiskCritical {
			cred.RiskReasons = append(cred.RiskReasons, "High-value credential type detected from name")
			if cred.Risk == RiskLow || cred.Risk == RiskMedium {
				cred.Risk = RiskHigh
			}
		}

		credentials = append(credentials, cred)
	}

	return credentials, nil
}

func (a *GitHubAuditor) auditGitHubApps(ctx context.Context, org string) ([]AuditedCredential, error) {
	var credentials []AuditedCredential

	installations, _, err := a.client.Organizations.ListInstallations(ctx, org, nil)
	if err != nil {
		return nil, err
	}

	for _, inst := range installations.Installations {
		cred := AuditedCredential{
			ID:        fmt.Sprintf("app-%d", inst.GetID()),
			Name:      inst.GetAppSlug(),
			Type:      "github_app",
			CreatedAt: inst.GetCreatedAt().Time,
			AgeInDays: int(time.Since(inst.GetCreatedAt().Time).Hours() / 24),
			Metadata: map[string]string{
				"app_id":               fmt.Sprintf("%d", inst.GetAppID()),
				"repository_selection": inst.GetRepositorySelection(),
			},
		}

		if suspendedAt := inst.GetSuspendedAt(); !suspendedAt.Time.IsZero() {
			cred.Metadata["suspended_at"] = suspendedAt.Time.Format(time.RFC3339)
		}

		if inst.Permissions != nil {
			cred.Scope = summarizeAppPermissions(inst.Permissions)
		}

		cred.Risk, cred.RiskReasons = a.assessCredentialRisk(&cred)

		if inst.GetRepositorySelection() == "all" {
			cred.RiskReasons = append(cred.RiskReasons, "Has access to ALL repositories")
			if cred.Risk != RiskCritical {
				cred.Risk = RiskHigh
			}
		}

		credentials = append(credentials, cred)
	}

	return credentials, nil
}

func (a *GitHubAuditor) assessCredentialRisk(cred *AuditedCredential) (RiskLevel, []string) {
	var reasons []string
	risk := RiskLow

	now := time.Now()

	if cred.AgeInDays > a.thresholds.MaxAgeDays*3 {
		reasons = append(reasons, fmt.Sprintf("Very old: %d days (max recommended: %d)", cred.AgeInDays, a.thresholds.MaxAgeDays))
		risk = RiskCritical
	} else if cred.AgeInDays > a.thresholds.MaxAgeDays {
		reasons = append(reasons, fmt.Sprintf("Stale: %d days old (max recommended: %d)", cred.AgeInDays, a.thresholds.MaxAgeDays))
		if risk < RiskHigh {
			risk = RiskHigh
		}
	}

	if cred.LastUsedAt != nil {
		cred.DormantDays = int(now.Sub(*cred.LastUsedAt).Hours() / 24)
		if cred.DormantDays > a.thresholds.MaxDormantDays*3 {
			reasons = append(reasons, fmt.Sprintf("Dormant: not used in %d days", cred.DormantDays))
			if risk < RiskHigh {
				risk = RiskHigh
			}
		} else if cred.DormantDays > a.thresholds.MaxDormantDays {
			reasons = append(reasons, fmt.Sprintf("Potentially dormant: not used in %d days", cred.DormantDays))
			if risk < RiskMedium {
				risk = RiskMedium
			}
		}
	}

	if cred.LastRotated != nil {
		daysSinceRotation := int(now.Sub(*cred.LastRotated).Hours() / 24)
		if daysSinceRotation > a.thresholds.MaxRotationDays*2 {
			reasons = append(reasons, fmt.Sprintf("Rotation overdue: last rotated %d days ago", daysSinceRotation))
			if risk < RiskHigh {
				risk = RiskHigh
			}
		} else if daysSinceRotation > a.thresholds.MaxRotationDays {
			reasons = append(reasons, fmt.Sprintf("Should rotate: last rotated %d days ago", daysSinceRotation))
			if risk < RiskMedium {
				risk = RiskMedium
			}
		}
	} else if cred.AgeInDays > a.thresholds.MaxRotationDays {
		reasons = append(reasons, "Never rotated since creation")
		if risk < RiskMedium {
			risk = RiskMedium
		}
	}

	if cred.ExpiresAt != nil {
		if cred.ExpiresAt.Before(now) {
			reasons = append(reasons, "EXPIRED but still exists")
			risk = RiskCritical
		} else if cred.ExpiresAt.Before(now.Add(time.Duration(a.thresholds.ExpirationWarning) * 24 * time.Hour)) {
			reasons = append(reasons, fmt.Sprintf("Expires in %d days", int(cred.ExpiresAt.Sub(now).Hours()/24)))
			if risk < RiskMedium {
				risk = RiskMedium
			}
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "Within recommended thresholds")
	}

	return risk, reasons
}

func (a *GitHubAuditor) calculateSummary(creds []AuditedCredential) AuditSummary {
	summary := AuditSummary{
		TotalCredentials: len(creds),
	}

	now := time.Now()

	for _, cred := range creds {
		switch cred.Risk {
		case RiskCritical:
			summary.CriticalRisk++
		case RiskHigh:
			summary.HighRisk++
		case RiskMedium:
			summary.MediumRisk++
		case RiskLow:
			summary.LowRisk++
		}

		if cred.AgeInDays > a.thresholds.MaxAgeDays {
			summary.StaleCount++
		}

		if cred.DormantDays > a.thresholds.MaxDormantDays {
			summary.DormantCount++
		}

		if cred.LastRotated == nil && cred.AgeInDays > a.thresholds.MaxRotationDays {
			summary.NeverRotatedCount++
		}

		if cred.ExpiresAt != nil {
			if cred.ExpiresAt.Before(now) {
				summary.ExpiredCount++
			} else if cred.ExpiresAt.Before(now.Add(time.Duration(a.thresholds.ExpirationWarning) * 24 * time.Hour)) {
				summary.ExpiringCount++
			}
		}
	}

	return summary
}

func isHighValueSecretName(name string) bool {
	highValue := []string{
		"AWS_SECRET", "AWS_ACCESS_KEY", "PRIVATE_KEY", "GPG_PRIVATE",
		"SSH_KEY", "DEPLOY_KEY", "NPM_TOKEN", "DOCKER_PASSWORD",
		"KUBECONFIG", "DATABASE_PASSWORD", "DB_PASSWORD", "PROD_",
		"PRODUCTION_", "MASTER_KEY", "ENCRYPTION_KEY", "SIGNING_KEY",
	}

	upper := strings.ToUpper(name)
	for _, hv := range highValue {
		if strings.Contains(upper, hv) {
			return true
		}
	}
	return false
}

func summarizeAppPermissions(perms *github.InstallationPermissions) string {
	var parts []string

	if perms.Administration != nil && *perms.Administration == "write" {
		parts = append(parts, "admin:write")
	}
	if perms.Contents != nil && *perms.Contents == "write" {
		parts = append(parts, "contents:write")
	}
	if perms.Secrets != nil && *perms.Secrets == "write" {
		parts = append(parts, "secrets:write")
	}
	if perms.Actions != nil && *perms.Actions == "write" {
		parts = append(parts, "actions:write")
	}

	if len(parts) == 0 {
		return "read-only"
	}
	return strings.Join(parts, ", ")
}

func riskOrder(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 0
	case RiskHigh:
		return 1
	case RiskMedium:
		return 2
	case RiskLow:
		return 3
	default:
		return 4
	}
}
