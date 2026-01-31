/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/spf13/cobra"
)

var (
	writeBack bool
	indent    string

	fmtCmd = &cobra.Command{
		Use:   "fmt",
		Short: "Format dae config file.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}

			data, err := os.ReadFile(cfgFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			var indentStr string
			switch indent {
			case "t":
				indentStr = "\t"
			case "2":
				indentStr = strings.Repeat(" ", 2)
			case "4":
				indentStr = strings.Repeat(" ", 4)
			case "8":
				indentStr = strings.Repeat(" ", 8)
			default:
				fmt.Printf("Invalid indent: %s. Must be t, 2, 4, or 8.\n", indent)
				os.Exit(1)
			}

			formatted, err := config_parser.FormatWithIndent(string(data), indentStr)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if writeBack {
				if err := os.WriteFile(cfgFile, []byte(formatted), 0644); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				return
			}

			fmt.Print(formatted)
		},
	}
)

func init() {
	rootCmd.AddCommand(fmtCmd)

	fmtCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	fmtCmd.PersistentFlags().BoolVarP(&writeBack, "write", "w", false, "write result back to file")
	fmtCmd.PersistentFlags().StringVarP(&indent, "indent", "i", "t", "indent with tab(t) or 2, 4, 8 spaces")
}
