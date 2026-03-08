package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	gogithub "github.com/google/go-github/v60/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/Nexora-NHI/nexora-cli/internal/audit"
)

var (
	auditOrg        string
	auditToken      string
	auditOutput     string
	auditFormat     string
	auditMaxAge     int
	auditMaxDormant int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit credential lifecycle (age, rotation, dormancy)",
	Long: `Audit credentials for lifecycle issues that file scanners cannot detect.

This uses platform APIs to check:
  • Credential age (when was it created?)
  • Last rotation (has it ever been rotated?)
  • Dormancy (when was it last used?)
  • Expiration status

No other scanner can do this - they only read static files.

Examples:
  # Audit GitHub org
  nexora audit github --org my-org

  # Custom thresholds
  nexora audit github --org my-org --max-age 60 --max-dormant 14

  # Export results
  nexora audit github --org my-org --format json --output audit.json`,
}

var auditGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Audit GitHub credentials",
	Long: `Audit GitHub credentials including:
  • Deploy keys (SSH keys for repo access)
  • Organization secrets (credentials for Actions)
  • GitHub Apps (installed applications)

Checks for stale, dormant, and never-rotated credentials.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if auditOrg == "" {
			return fmt.Errorf("--org required")
		}
		if auditToken == "" {
			auditToken = os.Getenv("GITHUB_TOKEN")
		}
		if auditToken == "" {
			return fmt.Errorf("GitHub token required: use --token or set GITHUB_TOKEN")
		}
		return nil
	},
	RunE: runAuditGitHub,
}

func runAuditGitHub(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: auditToken})
	tc := oauth2.NewClient(ctx, ts)
	client := gogithub.NewClient(tc)

	thresholds := audit.DefaultThresholds()
	if auditMaxAge > 0 {
		thresholds.MaxAgeDays = auditMaxAge
	}
	if auditMaxDormant > 0 {
		thresholds.MaxDormantDays = auditMaxDormant
	}

	auditor := audit.NewGitHubAuditor(client, thresholds)

	fmt.Printf("Auditing credentials in %s...\n", auditOrg)
	fmt.Printf("Thresholds: max age %d days, max dormant %d days\n\n", thresholds.MaxAgeDays, thresholds.MaxDormantDays)

	result, err := auditor.AuditOrg(ctx, auditOrg)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("CREDENTIAL AUDIT: %s\n", auditOrg)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("\nTotal Credentials: %d\n\n", result.Summary.TotalCredentials)

	fmt.Println("By Risk Level:")
	if result.Summary.CriticalRisk > 0 {
		fmt.Printf("  🔴 CRITICAL: %d\n", result.Summary.CriticalRisk)
	}
	if result.Summary.HighRisk > 0 {
		fmt.Printf("  🟠 HIGH:     %d\n", result.Summary.HighRisk)
	}
	if result.Summary.MediumRisk > 0 {
		fmt.Printf("  🟡 MEDIUM:   %d\n", result.Summary.MediumRisk)
	}
	if result.Summary.LowRisk > 0 {
		fmt.Printf("  🟢 LOW:      %d\n", result.Summary.LowRisk)
	}

	fmt.Println("\nIssues Detected:")
	if result.Summary.StaleCount > 0 {
		fmt.Printf("  ⏰ Stale (>%d days old):        %d\n", thresholds.MaxAgeDays, result.Summary.StaleCount)
	}
	if result.Summary.DormantCount > 0 {
		fmt.Printf("  💤 Dormant (unused >%d days):   %d\n", thresholds.MaxDormantDays, result.Summary.DormantCount)
	}
	if result.Summary.NeverRotatedCount > 0 {
		fmt.Printf("  🔄 Never rotated:               %d\n", result.Summary.NeverRotatedCount)
	}

	if result.Summary.CriticalRisk > 0 || result.Summary.HighRisk > 0 {
		fmt.Println("\n═══════════════════════════════════════════════════════════")
		fmt.Println("CREDENTIALS REQUIRING IMMEDIATE ATTENTION")
		fmt.Println("═══════════════════════════════════════════════════════════")

		for _, cred := range result.Credentials {
			if cred.Risk != audit.RiskCritical && cred.Risk != audit.RiskHigh {
				continue
			}

			riskIcon := "🟠"
			if cred.Risk == audit.RiskCritical {
				riskIcon = "🔴"
			}

			fmt.Printf("\n%s %s [%s]\n", riskIcon, cred.Name, strings.ToUpper(string(cred.Risk)))
			fmt.Printf("   Type: %s | Age: %d days\n", cred.Type, cred.AgeInDays)
			if cred.Scope != "" {
				fmt.Printf("   Scope: %s\n", cred.Scope)
			}
			fmt.Printf("   Issues:\n")
			for _, reason := range cred.RiskReasons {
				fmt.Printf("     • %s\n", reason)
			}
		}
	}

	if auditOutput != "" {
		var data []byte
		var err error

		switch auditFormat {
		case "json":
			data, err = json.MarshalIndent(result, "", "  ")
		default:
			data, err = json.MarshalIndent(result, "", "  ")
		}

		if err != nil {
			return err
		}

		if err := os.WriteFile(auditOutput, data, 0644); err != nil {
			return err
		}
		fmt.Printf("\n📄 Results written to: %s\n", auditOutput)
	}

	if result.Summary.CriticalRisk > 0 {
		fmt.Println("\n⚠️  Critical issues found. Review and remediate immediately.")
		os.Exit(1)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditGitHubCmd)

	auditGitHubCmd.Flags().StringVar(&auditOrg, "org", "", "GitHub organization to audit")
	auditGitHubCmd.Flags().StringVar(&auditToken, "token", "", "GitHub token (or set GITHUB_TOKEN)")
	auditGitHubCmd.Flags().StringVar(&auditOutput, "output", "", "Write results to file")
	auditGitHubCmd.Flags().StringVar(&auditFormat, "format", "json", "Output format: json")
	auditGitHubCmd.Flags().IntVar(&auditMaxAge, "max-age", 90, "Max credential age in days before flagging")
	auditGitHubCmd.Flags().IntVar(&auditMaxDormant, "max-dormant", 30, "Max days unused before flagging as dormant")
}
