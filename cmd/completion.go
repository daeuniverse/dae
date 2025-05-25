/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	completionCmd = &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Output shell completion code for the specified shell (bash, zsh or fish)",
		Long:      "Output shell completion code for the specified shell (bash, zsh or fish).",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		Hidden:    true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := getCompletion(args[0], cmd.Parent())
			if err != nil {
				return err
			}

			fmt.Print(out)
			return nil
		},
	}
)

// return the auto completion shell script, if supported
func getCompletion(sh string, parent *cobra.Command) (string, error) {
	var err error
	var buf bytes.Buffer

	switch sh {
	case "bash":
		err = parent.GenBashCompletion(&buf)
	case "zsh":
		err = parent.GenZshCompletion(&buf)
	case "fish":
		err = parent.GenFishCompletion(&buf, true)
	default:
		err = errors.New("unsupported shell type (must be bash, zsh or fish): " + sh)
	}

	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
func init() {
	rootCmd.AddCommand(completionCmd)
}
