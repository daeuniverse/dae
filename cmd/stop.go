/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/spf13/cobra"
)

var (
	stopImmediate bool
	stopTimeout   time.Duration
	stopCmd       = &cobra.Command{
		Use:   "stop [pid]",
		Short: "To stop a running dae process.",
		Run: func(cmd *cobra.Command, args []string) {
			internal.AutoSu()

			pid, err := resolveTargetPID(args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if err := stopProcess(pid, stopImmediate, stopTimeout); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("OK")
		},
	}
)

func init() {
	rootCmd.AddCommand(stopCmd)
	stopCmd.PersistentFlags().BoolVarP(&stopImmediate, "immediate", "i", false, "Abort active connections and stop immediately.")
	stopCmd.PersistentFlags().DurationVar(&stopTimeout, "timeout", 30*time.Second, "Maximum time to wait for the process to exit.")
}
