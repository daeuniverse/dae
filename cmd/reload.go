/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/spf13/cobra"
)

var (
	abort     bool
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
			if abort {
				if f, err := os.Create(AbortFile); err == nil {
					f.Close()
				}
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
	reloadCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
