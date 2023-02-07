/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package main

import (
	"flag"
	"fmt"
	"github.com/v2rayA/dae/control"
	"os"
)

func main() {
	var output string
	flag.StringVar(&output, "o", "", "Place the output into <file>.")
	flag.Parse()

	if output == "" {
		fmt.Println("Please provide flag \"-o <file>\"")
		os.Exit(1)
	}
	fmt.Printf("Generating %v\n", output)
	control.GenerateObjects(output)
	fmt.Printf("Generated %v\n", output)
}
