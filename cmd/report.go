package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/bundle"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/output"
	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/version"
	"github.com/spf13/cobra"
)

var (
	reportBundle   string
	reportInput    string
	reportFormat   string
	reportOutput   string
	reportSeverity string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate or bundle reports from a findings JSON file",
	Long: `Convert a findings JSON file to another format, or produce an integrity-checked evidence bundle.

Example:
  nexora report --input findings.json --format sarif --output findings.sarif
  nexora report --input findings.json --bundle ./evidence-bundle/`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if reportInput == "" {
			return fmt.Errorf("--input is required")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(reportInput)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}

		var jsonReport struct {
			ScanID   string            `json:"scan_id"`
			Findings []finding.Finding `json:"findings"`
		}
		if err := json.Unmarshal(data, &jsonReport); err != nil {
			return fmt.Errorf("parse input JSON: %w", err)
		}

		findings := jsonReport.Findings
		scanID := jsonReport.ScanID
		if scanID == "" {
			scanID = uuid.New().String()
		}

		if reportSeverity != "" {
			threshold, err := parseSeverityFlag(reportSeverity)
			if err != nil {
				return fmt.Errorf("invalid --severity: %w", err)
			}
			findings = finding.Filter(findings, threshold)
		}

		if reportBundle != "" {
			return bundle.Write(reportBundle, scanID, version.Version, findings)
		}

		return writeFindings(cmd, findings, reportFormat, reportOutput, scanID)
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVar(&reportInput, "input", "", "path to findings JSON file")
	reportCmd.Flags().StringVar(&reportBundle, "bundle", "", "create integrity-checked evidence bundle in this directory")
	reportCmd.Flags().StringVar(&reportFormat, "format", "table", "output format: table|json|sarif|ocsf")
	reportCmd.Flags().StringVar(&reportOutput, "output", "", "write output to file (default: stdout)")
	reportCmd.Flags().StringVar(&reportSeverity, "severity", "", "filter to minimum severity: info|low|medium|high|critical")
}

func writeFindings(cmd *cobra.Command, findings []finding.Finding, format, outputPath, scanID string) error {
	var w io.Writer
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	} else {
		w = cmd.OutOrStdout()
	}

	if scanID == "" {
		scanID = uuid.New().String()
	}

	switch format {
	case "json":
		return output.WriteJSON(w, scanID, version.Version, findings)
	case "sarif":
		return output.WriteSARIF(w, version.Version, findings)
	case "ocsf":
		return output.WriteOCSF(w, version.Version, findings)
	default:
		return output.WriteTable(w, findings)
	}
}
