/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

const (
	AbortFile = "/var/run/dae.abort"
)

var (
	Version = "unknown"
	rootCmd = &cobra.Command{
		Use:     "dae [flags] [command [argument ...]]",
		Short:   "dae is a high-performance transparent proxy solution.",
		Long:    `dae is a high-performance transparent proxy solution.`,
		Version: Version,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
)

func init() {
	config.Version = Version
	rootCmd.Version = strings.Join([]string{
		Version,
		fmt.Sprintf("go runtime %v %v/%v", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		"Copyright (c) 2022-2024 @daeuniverse",
		"License GNU AGPLv3 <https://github.com/daeuniverse/dae/blob/main/LICENSE>",
	}, "\n")
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
