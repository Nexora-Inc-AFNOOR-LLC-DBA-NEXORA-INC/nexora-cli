package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for NHI risk patterns",
	Long:  "Scan GitHub Actions workflows, Kubernetes manifests, or IaC files for NHI risk patterns.",
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
