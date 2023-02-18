//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package main

import (
	"github.com/json-iterator/go/extra"
	"github.com/v2rayA/dae/cmd"
	"net/http"
	"os"
	"time"
)

func main() {
	extra.RegisterFuzzyDecoders()

	http.DefaultClient.Timeout = 30 * time.Second
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
