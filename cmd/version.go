package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Nexora-NHI/nexora-cli/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "nexora-cli %s (commit: %s, built: %s)\n",
			version.Version, version.Commit, version.BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
