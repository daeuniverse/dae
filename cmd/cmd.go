package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

const (
	AbortFile = "/var/run/dae.abort"
)

var (
	Version = "unknown"
	rootCmd = &cobra.Command{
		Use:     "dae [flags] [command [argument ...]]",
		Short:   "dae is a high-performance transparent proxy solution.",
		Long:    `dae is a high-performance transparent proxy solution.`,
		Version: Version,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
)

func init() {
	config.Version = Version
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
