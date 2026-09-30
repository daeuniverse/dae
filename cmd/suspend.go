/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	stderrors "errors"
	"fmt"
	"os"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/spf13/cobra"
)

var (
	suspendCmd = &cobra.Command{
		Use:   "suspend [pid]",
		Short: "To suspend dae. This command puts dae into no-load state. Recover it by 'dae reload'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			internal.AutoSu()
			pid, err := resolveReloadPID(args)
			if err != nil {
				_ = cmd.Help()
				return err
			}
			if err := ensureDaemonAlive(pid); err != nil {
				return err
			}
			if abort {
				if f, err := os.Create(AbortFile); err == nil {
					_ = f.Close()
				}
			}
			if err = syscall.Kill(pid, syscall.SIGUSR2); err != nil {
				if stderrors.Is(err, syscall.ESRCH) {
					cleanupStaleDaemonFiles()
					return fmt.Errorf("dae is not running (pid %d no longer exists)", pid)
				}
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "OK")
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(suspendCmd)
	suspendCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
