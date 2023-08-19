/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

 package cmd

 import (
	 "fmt"
	 "os"
     "time"
 
	 "github.com/spf13/cobra"
 )
 
 var (
	 honkCmd = &cobra.Command{
		 Use:   "honk",
		 Short: "Let dae call for you.",
		 Run: func(cmd *cobra.Command, args []string) {
				 fmt.Println("Honk! Honk! Honk! This is dae!")
                 fmt.Println("\a\a\a\x1b[1A")
                 time.Sleep(3 * 100 * time.Millisecond)
                 fmt.Println("\a\a\a\x1b[1A")
                 time.Sleep(3 * 100 * time.Millisecond)
                 fmt.Println("\a\a\a\x1b[1A")
				 os.Exit(0)
		 },
	 }
 )
 
 func init() {
	 rootCmd.AddCommand(honkCmd)
 }
 
