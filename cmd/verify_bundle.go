package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Nexora-NHI/nexora-cli/internal/bundle"
)

var verifyBundleCmd = &cobra.Command{
	Use:   "bundle <dir>",
	Short: "Verify integrity of an evidence bundle",
	Long: `Verify the SHA-256, SHA-512, and root hash of all files in an evidence bundle.

Exits 0 if all checks pass. Exits 1 if any check fails.

Example:
  nexora verify bundle ./evidence-bundle/`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := args[0]
		results, err := bundle.Verify(dir)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ERROR: %v\n", err)
			os.Exit(2)
		}

		allPassed := true
		for _, r := range results {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
				allPassed = false
			}
			if r.Passed {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s\n", status, r.File)
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s — %s\n", status, r.File, r.Reason)
			}
		}

		if !allPassed {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "\nBundle verification FAILED: one or more files have been modified.")
			os.Exit(1)
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nBundle verification PASSED.")
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify artifacts produced by nexora",
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.AddCommand(verifyBundleCmd)
}
