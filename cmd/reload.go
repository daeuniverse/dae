/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"strconv"
	"syscall"
)

var (
	reloadCmd = &cobra.Command{
		Use: "reload pid",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cmd.Help()
				os.Exit(1)
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil {
				cmd.Help()
				os.Exit(1)
			}
			syscall.Kill(pid, syscall.SIGUSR1)
		},
	}
)
