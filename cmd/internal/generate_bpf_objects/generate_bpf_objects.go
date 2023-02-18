/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
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
