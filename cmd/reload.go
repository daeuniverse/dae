/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

func readSignalProgressFile() (code byte, content string, err error) {
	b, err := os.ReadFile(SignalProgressFilePath)
	if err != nil {
		return 0, "", err
	}
	var firstLine string
	firstLine, content, _ = strings.Cut(string(b), "\n")
	if len(firstLine) != 1 {
		return 0, "", fmt.Errorf("unexpected format: %v", string(b))
	}
	code = firstLine[0]
	return code, content, nil
}

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
			// Read the first line of SignalProgressFilePath.
			code, _, err := readSignalProgressFile()
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError {
				// In progress.
				fmt.Printf("%v shows another reload operation is in progress.\n", SignalProgressFilePath)
				return
			}
			// Set the progress as ReloadSend.
			os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadSend}, 0644)
			// Send signal.
			if err = syscall.Kill(pid, syscall.SIGUSR1); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			time.Sleep(500 * time.Millisecond)
			code, _, _ = readSignalProgressFile()
			if code == consts.ReloadSend {
				// Old version dae is running.
				goto fallback
			}

			for {
				time.Sleep(200 * time.Millisecond)
				code, content, err := readSignalProgressFile()
				if err != nil {
					// Unexpecetd case.
					goto fallback
				}
				if code == consts.ReloadDone || code == consts.ReloadError {
					fmt.Println(content)
					return
				}
			}
		fallback:
			fmt.Println("OK")
		},
	}
)

func init() {
	rootCmd.AddCommand(reloadCmd)
	reloadCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
