/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/spf13/cobra"
)

var (
	restartImmediate bool
	restartTimeout   time.Duration
	restartCmd       = &cobra.Command{
		Use:   "restart [pid]",
		Short: "To restart a running dae process or dae.service.",
		Run: func(cmd *cobra.Command, args []string) {
			internal.AutoSu()

			pid, err := resolveTargetPID(args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			systemdManaged := isSystemdMainPID(pid)
			exe, procArgs, err := readProcessCommand(pid)
			if err != nil && !systemdManaged {
				fmt.Println(err)
				os.Exit(1)
			}
			if !systemdManaged && len(procArgs) == 0 {
				fmt.Printf("cannot restart pid %d: missing original command arguments\n", pid)
				os.Exit(1)
			}

			if err := stopProcess(pid, restartImmediate, restartTimeout); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if systemdManaged {
				cmd := exec.Command("systemctl", "start", daeSystemdUnit)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Println("OK")
				return
			}

			newPID, err := startDetachedProcess(exe, procArgs)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("OK (pid=%d)\n", newPID)
		},
	}
)

func init() {
	rootCmd.AddCommand(restartCmd)
	restartCmd.PersistentFlags().BoolVarP(&restartImmediate, "immediate", "i", false, "Abort active connections before restart.")
	restartCmd.PersistentFlags().DurationVar(&restartTimeout, "timeout", 30*time.Second, "Maximum time to wait for the old process to exit.")
}
