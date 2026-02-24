package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	gogithub "github.com/google/go-github/v60/github"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	ghscanner "github.com/Nexora-NHI/nexora-cli/internal/scanner/github"
)

var (
	ghOrg       string
	ghRepo      string
	ghToken     string
	ghFormat    string
	ghOutput    string
	ghSeverity  string
	ghBundle    string
	ghThreshold finding.Severity
)

var scanGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Scan GitHub Actions workflows via the GitHub API",
	Long: `Fetch and scan GitHub Actions workflow files from a repository or organisation.

Requires a GitHub token with 'repo' (or 'public_repo') scope.
Set via --token or GITHUB_TOKEN environment variable.

This is the ONLY command that makes network calls.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if ghOrg == "" && ghRepo == "" {
			return fmt.Errorf("--org or --repo is required")
		}
		tokenFromFlag := ghToken != ""
		if ghToken == "" {
			ghToken = os.Getenv("GITHUB_TOKEN")
		}
		if ghToken == "" {
			return fmt.Errorf("GitHub token required: use --token or set GITHUB_TOKEN")
		}
		if tokenFromFlag {
			log.Warn().Msg("--token flag exposes the token in process list and shell history; prefer GITHUB_TOKEN env var")
		}
		sev, err := parseSeverityFlag(ghSeverity)
		if err != nil {
			return fmt.Errorf("invalid --severity: %w", err)
		}
		ghThreshold = sev
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ghToken})
		tc := oauth2.NewClient(ctx, ts)
		client := gogithub.NewClient(tc)

		var repos []string
		if ghRepo != "" {
			repos = append(repos, ghRepo)
		} else {
			log.Info().Str("org", ghOrg).Msg("listing repositories")
			opt := &gogithub.RepositoryListByOrgOptions{ListOptions: gogithub.ListOptions{PerPage: 100}}
			for {
				page, resp, err := client.Repositories.ListByOrg(ctx, ghOrg, opt)
				if err != nil {
					return fmt.Errorf("list repos for org %s: %w", ghOrg, err)
				}
				for _, r := range page {
					repos = append(repos, r.GetFullName())
				}
				if resp.NextPage == 0 {
					break
				}
				opt.Page = resp.NextPage
			}
		}

		scanner := ghscanner.New()
		var allFindings []finding.Finding

		for _, repoFullName := range repos {
			owner, repoName, err := splitRepo(repoFullName)
			if err != nil {
				log.Warn().Str("repo", repoFullName).Msg("invalid repo name, skipping")
				continue
			}
			log.Info().Str("repo", repoFullName).Msg("scanning workflows")

			_, dirContents, _, err := client.Repositories.GetContents(ctx, owner, repoName, ".github/workflows", nil)
			if err != nil {
				var rle *gogithub.RateLimitError
				if errors.As(err, &rle) {
					return fmt.Errorf("GitHub API rate limit exceeded: resets at %s", rle.Rate.Reset.Time)
				}
				log.Warn().Err(err).Str("repo", repoFullName).Msg("cannot list workflows, skipping")
				continue
			}

			for _, item := range dirContents {
				if item.GetType() != "file" {
					continue
				}
				name := item.GetName()
				if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
					continue
				}

				fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, item.GetPath(), nil)
				if err != nil {
					log.Warn().Err(err).Str("file", item.GetPath()).Msg("cannot fetch file, skipping")
					continue
				}

				content, err := fileContent.GetContent()
				if err != nil {
					log.Warn().Err(err).Str("file", item.GetPath()).Msg("cannot decode file content, skipping")
					continue
				}

				filePath := fmt.Sprintf("%s/%s", repoFullName, item.GetPath())
				findings, err := scanner.ScanBytes([]byte(content), filePath)
				if err != nil {
					log.Warn().Err(err).Str("file", filePath).Msg("scan error")
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		}

		finding.Sort(allFindings)
		filtered := finding.Filter(allFindings, ghThreshold)

		if err := writeFindings(cmd, filtered, ghFormat, ghOutput, ghBundle, ""); err != nil {
			return err
		}

		if len(filtered) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func splitRepo(fullName string) (owner, repo string, err error) {
	for i, c := range fullName {
		if c == '/' {
			return fullName[:i], fullName[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("expected owner/repo format, got %q", fullName)
}

func init() {
	scanCmd.AddCommand(scanGitHubCmd)
	scanGitHubCmd.Flags().StringVar(&ghOrg, "org", "", "GitHub organisation to scan")
	scanGitHubCmd.Flags().StringVar(&ghRepo, "repo", "", "GitHub repository to scan (owner/repo)")
	scanGitHubCmd.Flags().StringVar(&ghToken, "token", "", "GitHub token (or set GITHUB_TOKEN)")
	scanGitHubCmd.Flags().StringVar(&ghFormat, "format", "table", "output format: table|json|sarif|ocsf")
	scanGitHubCmd.Flags().StringVar(&ghOutput, "output", "", "write output to file (default: stdout)")
	scanGitHubCmd.Flags().StringVar(&ghSeverity, "severity", "info", "minimum severity threshold: info|low|medium|high|critical")
	scanGitHubCmd.Flags().StringVar(&ghBundle, "bundle", "", "create integrity-checked evidence bundle in this directory")
}
