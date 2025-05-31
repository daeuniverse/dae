/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"

	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

var (
	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "To export some information for UI developers.",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	exportOutlineCmd = &cobra.Command{
		Use:   "outline",
		Short: "To export config structure.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(config.ExportOutlineJson(Version))
		},
	}
)

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportOutlineCmd)
}
