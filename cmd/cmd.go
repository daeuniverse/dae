package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	v       *viper.Viper
	Version = "unknown"
	verbose int
	rootCmd = &cobra.Command{
		Use:     "dae [flags] [command [argument ...]]",
		Short:   "dae is a lightweight and high-performance transparent proxy solution.",
		Long:    `dae is a lightweight and high-performance transparent proxy solution.`,
		Version: Version,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func NewLogger(verbose int) *logrus.Logger {
	log := logrus.New()

	var level logrus.Level
	switch verbose {
	case 0:
		level = logrus.WarnLevel
	case 1:
		level = logrus.InfoLevel
	default:
		level = logrus.TraceLevel
	}
	log.SetLevel(level)

	return log
}
