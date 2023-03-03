package cmd

import (
	"github.com/spf13/cobra"
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

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(reloadCmd)
}
