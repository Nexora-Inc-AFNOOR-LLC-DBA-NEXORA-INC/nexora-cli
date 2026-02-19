package cmd

import (
	"fmt"
	"os"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/bundle"
	"github.com/spf13/cobra"
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
			fmt.Fprintf(cmd.ErrOrStderr(), "ERROR: %v\n", err)
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
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s\n", status, r.File)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s — %s\n", status, r.File, r.Reason)
			}
		}

		if !allPassed {
			fmt.Fprintln(cmd.ErrOrStderr(), "\nBundle verification FAILED: one or more files have been modified.")
			os.Exit(1)
		}

		fmt.Fprintln(cmd.OutOrStdout(), "\nBundle verification PASSED.")
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
