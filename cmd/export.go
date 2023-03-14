/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/daeuniverse/dae/config"
)

var (
	exportCmd = &cobra.Command{
		Use: "export",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	exportOutlineCmd = &cobra.Command{
		Use: "outline",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(config.ExportOutlineJson(Version))
		},
	}
)

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportOutlineCmd)
}
