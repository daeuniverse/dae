//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"net/http"
	"os"
	"time"

	"github.com/daeuniverse/dae/cmd"
	"github.com/daeuniverse/dae/common/json"
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	// _ "net/http/pprof"
)

func main() {
	// go http.ListenAndServe("0.0.0.0:8000", nil)
	jsoniter.RegisterTypeDecoder("bool", &json.FuzzyBoolDecoder{})
	extra.RegisterFuzzyDecoders()

	http.DefaultClient.Timeout = 30 * time.Second
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
