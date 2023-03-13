/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/v2rayA/dae/cmd/internal"
	"os"
	"strconv"
	"strings"
	"syscall"
)

var (
	reloadCmd = &cobra.Command{
		Use:   "reload [pid]",
		Short: "To reload config file without interrupt connections.",
		Run: func(cmd *cobra.Command, args []string) {
			internal.AutoSu()
			if len(args) == 0 {
				_pid, err := os.ReadFile(PidFilePath)
				if err != nil {
					fmt.Println("Failed to read pid file:", err)
					os.Exit(1)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil {
				cmd.Help()
				os.Exit(1)
			}
			if err = syscall.Kill(pid, syscall.SIGUSR1); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("OK")
		},
	}
)

func init() {
	rootCmd.AddCommand(reloadCmd)
}
