/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate dae config",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			// Read config from --config cfgFile.
			_, err := readConfig(cfgFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("OK")
		},
	}
)

func init() {
	validateCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}
