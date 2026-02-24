package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	iacscanner "github.com/Nexora-NHI/nexora-cli/internal/scanner/iac"
)

var (
	iacPath      string
	iacFormat    string
	iacOutput    string
	iacSeverity  string
	iacThreshold finding.Severity
)

var scanIaCCmd = &cobra.Command{
	Use:   "iac",
	Short: "Scan IaC files for NHI risk patterns",
	Long:  "Scan local Terraform, CloudFormation, and other IaC files for NHI risk patterns. No network calls are made.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if iacPath == "" {
			return fmt.Errorf("--path is required")
		}
		sev, err := parseSeverityFlag(iacSeverity)
		if err != nil {
			return fmt.Errorf("invalid --severity: %w", err)
		}
		iacThreshold = sev
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanner := iacscanner.New()
		findings, err := scanner.ScanPath(iacPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		finding.Sort(findings)
		filtered := finding.Filter(findings, iacThreshold)

		if err := writeFindings(cmd, filtered, iacFormat, iacOutput, "", ""); err != nil {
			return err
		}

		if len(filtered) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanCmd.AddCommand(scanIaCCmd)
	scanIaCCmd.Flags().StringVar(&iacPath, "path", "", "path to IaC directory or file")
	scanIaCCmd.Flags().StringVar(&iacFormat, "format", "table", "output format: table|json|sarif|ocsf")
	scanIaCCmd.Flags().StringVar(&iacOutput, "output", "", "write output to file (default: stdout)")
	scanIaCCmd.Flags().StringVar(&iacSeverity, "severity", "info", "minimum severity threshold: info|low|medium|high|critical")
}
