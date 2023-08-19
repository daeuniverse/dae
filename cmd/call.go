/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

 package cmd

 import (
	 "fmt"
	 "os"
 
	 "github.com/spf13/cobra"
 )
 
 var (
	 honkCmd = &cobra.Command{
		 Use:   "honk",
		 Short: "Let dae call for you.",
		 Run: func(cmd *cobra.Command, args []string) {
				 fmt.Println("Honk! Honk! Honk! This is dae!")
				 os.Exit(1)
		 },
	 }
 )
 
 func init() {
	 rootCmd.AddCommand(honkCmd)
 }
 
