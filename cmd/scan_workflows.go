package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	ghscanner "github.com/Nexora-NHI/nexora-cli/internal/scanner/github"
)

var (
	wfPath      string
	wfFormat    string
	wfOutput    string
	wfSeverity  string
	wfBundle    string
	wfThreshold finding.Severity
)

var scanWorkflowsCmd = &cobra.Command{
	Use:   "workflows",
	Short: "Scan local GitHub Actions workflow files for NHI risk patterns",
	Long: `Scan local GitHub Actions workflow YAML files for NHI risk patterns.

No network calls are made. No token required.
Use this command to scan workflow files on disk — in CI, pre-commit, or locally.

For scanning a live GitHub organisation via the API, use: nexora scan github`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if wfPath == "" {
			return fmt.Errorf("--path is required")
		}
		sev, err := parseSeverityFlag(wfSeverity)
		if err != nil {
			return fmt.Errorf("invalid --severity: %w", err)
		}
		wfThreshold = sev
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanner := ghscanner.New()
		findings, err := scanner.ScanPath(wfPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		finding.Sort(findings)
		filtered := finding.Filter(findings, wfThreshold)

		if err := writeFindings(cmd, filtered, wfFormat, wfOutput, wfBundle, ""); err != nil {
			return err
		}

		if len(filtered) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanCmd.AddCommand(scanWorkflowsCmd)
	scanWorkflowsCmd.Flags().StringVar(&wfPath, "path", "", "path to workflow files directory or single file")
	scanWorkflowsCmd.Flags().StringVar(&wfFormat, "format", "table", "output format: table|json|sarif|ocsf")
	scanWorkflowsCmd.Flags().StringVar(&wfOutput, "output", "", "write output to file (default: stdout)")
	scanWorkflowsCmd.Flags().StringVar(&wfSeverity, "severity", "info", "minimum severity threshold: info|low|medium|high|critical")
	scanWorkflowsCmd.Flags().StringVar(&wfBundle, "bundle", "", "create integrity-checked evidence bundle in this directory")
}
