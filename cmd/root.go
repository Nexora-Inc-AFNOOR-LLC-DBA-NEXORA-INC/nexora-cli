package cmd

import (
	"os"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile  string
	logLevel string
	noColor  bool
)

var rootCmd = &cobra.Command{
	Use:   "nexora",
	Short: "nexora-cli — NHI risk scanner for GitHub Actions, Kubernetes, and IaC",
	Long: `nexora-cli is an open-source, read-only Non-Human Identity (NHI) risk scanner.

Scans GitHub Actions workflows, Kubernetes manifests, and IaC files for
machine identity risk patterns. Produces structured findings in table,
JSON, SARIF 2.1.0, and OCSF 1.1.0 formats.

No data is transmitted. No Nexora API is called. Read-only.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.nexora.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "log level (trace|debug|info|warn|error)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}

func initConfig() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(parseLevel(logLevel))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: noColor})

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			log.Warn().Err(err).Str("config", cfgFile).Msg("failed to read config")
		}
	}
}

func parseLevel(s string) zerolog.Level {
	l, err := zerolog.ParseLevel(s)
	if err != nil {
		return zerolog.WarnLevel
	}
	return l
}

func parseSeverityFlag(s string) (finding.Severity, error) {
	return finding.ParseSeverity(s)
}
