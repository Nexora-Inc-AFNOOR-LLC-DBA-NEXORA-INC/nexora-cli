package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Nexora-NHI/nexora-cli/internal/finding"
	k8sscanner "github.com/Nexora-NHI/nexora-cli/internal/scanner/k8s"
)

var (
	k8sPath      string
	k8sFormat    string
	k8sOutput    string
	k8sSeverity  string
	k8sThreshold finding.Severity
)

var scanK8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Scan Kubernetes manifests for NHI risk patterns",
	Long:  "Scan local Kubernetes YAML manifests for NHI risk patterns. No network calls are made.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if k8sPath == "" {
			return fmt.Errorf("--path is required")
		}
		sev, err := parseSeverityFlag(k8sSeverity)
		if err != nil {
			return fmt.Errorf("invalid --severity: %w", err)
		}
		k8sThreshold = sev
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanner := k8sscanner.New()
		findings, err := scanner.ScanPath(k8sPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		finding.Sort(findings)
		filtered := finding.Filter(findings, k8sThreshold)

		if err := writeFindings(cmd, filtered, k8sFormat, k8sOutput, "", ""); err != nil {
			return err
		}

		if len(filtered) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanCmd.AddCommand(scanK8sCmd)
	scanK8sCmd.Flags().StringVar(&k8sPath, "path", "", "path to Kubernetes manifests directory or file")
	scanK8sCmd.Flags().StringVar(&k8sFormat, "format", "table", "output format: table|json|sarif|ocsf")
	scanK8sCmd.Flags().StringVar(&k8sOutput, "output", "", "write output to file (default: stdout)")
	scanK8sCmd.Flags().StringVar(&k8sSeverity, "severity", "info", "minimum severity threshold: info|low|medium|high|critical")
}
