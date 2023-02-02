/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	var output string
	flag.StringVar(&output, "o", "", "Place the output into <file>.")
	flag.Parse()

	if output == "" {
		fmt.Println("Please provide flag \"-o <file>\"")
		os.Exit(1)
	}
	output, err := filepath.Abs(output)
	if err != nil {
		fmt.Printf("Failed to get absolute path of \"%v\": %v", output, err)
		os.Exit(1)
	}
	// Trick: write a dummy bpfObjectsLan{} and bpfObjectsWan{} before call control package.
	if err := os.WriteFile(output, []byte(`package control
type bpfObjectsLan struct{}
type bpfObjectsWan struct{}`), 0644); err != nil {
		fmt.Printf("Failed to write \"%v\": %v", output, err)
		os.Exit(1)
	}
	fmt.Printf("Generated dummy %v\n", output)
}
