package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v60/github"
	"gopkg.in/yaml.v3"
)

// GitHubGraphBuilder builds identity graphs from GitHub organizations
type GitHubGraphBuilder struct {
	client *github.Client
}

// NewGitHubGraphBuilder creates a new GitHub graph builder
func NewGitHubGraphBuilder(client *github.Client) *GitHubGraphBuilder {
	return &GitHubGraphBuilder{client: client}
}

// BuildOrgGraph builds a complete identity graph for a GitHub organization
func (b *GitHubGraphBuilder) BuildOrgGraph(ctx context.Context, org string) (*IdentityGraph, error) {
	g := NewIdentityGraph()

	if err := b.addGitHubApps(ctx, org, g); err != nil {
		return nil, err
	}

	if err := b.addWorkflows(ctx, org, g); err != nil {
		return nil, err
	}

	if err := b.addSecrets(ctx, org, g); err != nil {
		return nil, err
	}

	if err := b.addDeployKeys(ctx, org, g); err != nil {
		return nil, err
	}

	return g, nil
}

// BuildRepoGraph builds an identity graph for a single repository
func (b *GitHubGraphBuilder) BuildRepoGraph(ctx context.Context, owner, repo string) (*IdentityGraph, error) {
	g := NewIdentityGraph()

	if err := b.addRepoWorkflows(ctx, owner, repo, g); err != nil {
		return nil, err
	}

	if err := b.addRepoSecrets(ctx, owner, repo, g); err != nil {
		return nil, err
	}

	if err := b.addRepoDeployKeys(ctx, owner, repo, g); err != nil {
		return nil, err
	}

	return g, nil
}

func (b *GitHubGraphBuilder) addGitHubApps(ctx context.Context, org string, g *IdentityGraph) error {
	installations, _, err := b.client.Organizations.ListInstallations(ctx, org, nil)
	if err != nil {
		return err
	}

	for _, inst := range installations.Installations {
		node := &IdentityNode{
			ID:       fmt.Sprintf("app-%d", inst.GetID()),
			Name:     inst.GetAppSlug(),
			Type:     NodeTypeGitHubApp,
			Provider: "github",
			Risk:     assessAppRisk(inst),
			Metadata: map[string]string{
				"app_id":               fmt.Sprintf("%d", inst.GetAppID()),
				"repository_selection": inst.GetRepositorySelection(),
			},
		}

		if inst.Permissions != nil {
			node.Permissions = extractAppPermissions(inst.Permissions)
		}

		g.AddNode(node)
	}

	return nil
}

func (b *GitHubGraphBuilder) addWorkflows(ctx context.Context, org string, g *IdentityGraph) error {
	repos, _, err := b.client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		return err
	}

	for _, repo := range repos {
		if err := b.addRepoWorkflows(ctx, org, repo.GetName(), g); err != nil {
			continue
		}
	}

	return nil
}

func (b *GitHubGraphBuilder) addRepoWorkflows(ctx context.Context, owner, repo string, g *IdentityGraph) error {
	workflows, _, err := b.client.Actions.ListWorkflows(ctx, owner, repo, nil)
	if err != nil {
		return err
	}

	for _, wf := range workflows.Workflows {
		node := &IdentityNode{
			ID:       fmt.Sprintf("workflow-%d", wf.GetID()),
			Name:     fmt.Sprintf("%s/%s: %s", owner, repo, wf.GetName()),
			Type:     NodeTypeGitHubWorkflow,
			Provider: "github",
			Risk:     RiskMedium,
			Metadata: map[string]string{
				"repo": fmt.Sprintf("%s/%s", owner, repo),
				"path": wf.GetPath(),
			},
		}

		g.AddNode(node)

		content, _, _, err := b.client.Repositories.GetContents(ctx, owner, repo, wf.GetPath(), nil)
		if err == nil && content != nil {
			decodedContent, err := content.GetContent()
			if err == nil {
				b.analyzeWorkflowContent(decodedContent, node, g)
			}
		}
	}

	return nil
}

func (b *GitHubGraphBuilder) analyzeWorkflowContent(content string, workflowNode *IdentityNode, g *IdentityGraph) {
	var wf struct {
		Jobs map[string]struct {
			Permissions interface{} `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
		Permissions interface{} `yaml:"permissions"`
	}

	if err := yaml.Unmarshal([]byte(content), &wf); err != nil {
		return
	}

	hasWritePerms := false
	if perms, ok := wf.Permissions.(map[string]interface{}); ok {
		for _, v := range perms {
			if v == "write" {
				hasWritePerms = true
				break
			}
		}
	} else if wf.Permissions == "write-all" {
		hasWritePerms = true
	}

	if hasWritePerms {
		workflowNode.Risk = RiskHigh
	}

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			for envKey := range step.Env {
				if strings.Contains(strings.ToUpper(envKey), "SECRET") ||
					strings.Contains(strings.ToUpper(envKey), "TOKEN") ||
					strings.Contains(strings.ToUpper(envKey), "KEY") {
					
					secretNode := &IdentityNode{
						ID:       fmt.Sprintf("secret-%s", envKey),
						Name:     envKey,
						Type:     NodeTypeGitHubSecret,
						Provider: "github",
						Risk:     RiskHigh,
					}
					g.AddNode(secretNode)
					g.AddEdge(workflowNode.ID, secretNode.ID, RelationUsesSecret, "workflow env")
				}
			}
		}
	}
}

func (b *GitHubGraphBuilder) addSecrets(ctx context.Context, org string, g *IdentityGraph) error {
	secrets, _, err := b.client.Actions.ListOrgSecrets(ctx, org, nil)
	if err != nil {
		return err
	}

	for _, secret := range secrets.Secrets {
		node := &IdentityNode{
			ID:       fmt.Sprintf("secret-%s", secret.Name),
			Name:     secret.Name,
			Type:     NodeTypeGitHubSecret,
			Provider: "github",
			Risk:     assessSecretRisk(secret.Name),
			Metadata: map[string]string{
				"visibility": secret.Visibility,
			},
		}

		g.AddNode(node)
	}

	return nil
}

func (b *GitHubGraphBuilder) addRepoSecrets(ctx context.Context, owner, repo string, g *IdentityGraph) error {
	secrets, _, err := b.client.Actions.ListRepoSecrets(ctx, owner, repo, nil)
	if err != nil {
		return err
	}

	for _, secret := range secrets.Secrets {
		node := &IdentityNode{
			ID:       fmt.Sprintf("secret-%s-%s", repo, secret.Name),
			Name:     fmt.Sprintf("%s/%s: %s", owner, repo, secret.Name),
			Type:     NodeTypeGitHubSecret,
			Provider: "github",
			Risk:     assessSecretRisk(secret.Name),
			Metadata: map[string]string{
				"repo": fmt.Sprintf("%s/%s", owner, repo),
			},
		}

		g.AddNode(node)
	}

	return nil
}

func (b *GitHubGraphBuilder) addDeployKeys(ctx context.Context, org string, g *IdentityGraph) error {
	repos, _, err := b.client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		return err
	}

	for _, repo := range repos {
		if err := b.addRepoDeployKeys(ctx, org, repo.GetName(), g); err != nil {
			continue
		}
	}

	return nil
}

func (b *GitHubGraphBuilder) addRepoDeployKeys(ctx context.Context, owner, repo string, g *IdentityGraph) error {
	keys, _, err := b.client.Repositories.ListKeys(ctx, owner, repo, nil)
	if err != nil {
		return err
	}

	for _, key := range keys {
		risk := RiskMedium
		if !key.GetReadOnly() {
			risk = RiskHigh
		}

		node := &IdentityNode{
			ID:       fmt.Sprintf("deploy-key-%d", key.GetID()),
			Name:     fmt.Sprintf("%s/%s: %s", owner, repo, key.GetTitle()),
			Type:     NodeTypeDeployKey,
			Provider: "github",
			Risk:     risk,
			Metadata: map[string]string{
				"repo":      fmt.Sprintf("%s/%s", owner, repo),
				"read_only": fmt.Sprintf("%v", key.GetReadOnly()),
			},
		}

		if !key.GetReadOnly() {
			node.Permissions = []string{"contents:write"}
		} else {
			node.Permissions = []string{"contents:read"}
		}

		g.AddNode(node)
	}

	return nil
}

func assessAppRisk(inst *github.Installation) RiskLevel {
	if inst.GetRepositorySelection() == "all" {
		return RiskHigh
	}

	if inst.Permissions != nil {
		if inst.Permissions.Administration != nil && *inst.Permissions.Administration == "write" {
			return RiskCritical
		}
		if inst.Permissions.Secrets != nil && *inst.Permissions.Secrets == "write" {
			return RiskHigh
		}
	}

	return RiskMedium
}

func extractAppPermissions(perms *github.InstallationPermissions) []string {
	var permissions []string

	if perms.Administration != nil && *perms.Administration != "" {
		permissions = append(permissions, fmt.Sprintf("administration:%s", *perms.Administration))
	}
	if perms.Contents != nil && *perms.Contents != "" {
		permissions = append(permissions, fmt.Sprintf("contents:%s", *perms.Contents))
	}
	if perms.Secrets != nil && *perms.Secrets != "" {
		permissions = append(permissions, fmt.Sprintf("secrets:%s", *perms.Secrets))
	}
	if perms.Actions != nil && *perms.Actions != "" {
		permissions = append(permissions, fmt.Sprintf("actions:%s", *perms.Actions))
	}

	return permissions
}

func assessSecretRisk(name string) RiskLevel {
	highValue := []string{
		"AWS_SECRET", "AWS_ACCESS_KEY", "PRIVATE_KEY", "GPG_PRIVATE",
		"SSH_KEY", "DEPLOY_KEY", "NPM_TOKEN", "DOCKER_PASSWORD",
		"KUBECONFIG", "DATABASE_PASSWORD", "DB_PASSWORD", "PROD_",
		"PRODUCTION_", "MASTER_KEY", "ENCRYPTION_KEY", "SIGNING_KEY",
	}

	upper := strings.ToUpper(name)
	for _, hv := range highValue {
		if strings.Contains(upper, hv) {
			return RiskCritical
		}
	}

	return RiskHigh
}
