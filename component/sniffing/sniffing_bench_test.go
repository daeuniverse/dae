/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"testing"

	"github.com/daeuniverse/dae/common"

	"github.com/daeuniverse/outbound/pkg/fastrand"
)

var (
	httpMethodSet map[string]struct{}
	benchmarkSink string
)

func init() {
	httpMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "CONNECT", "TRACE"}
	httpMethodSet = make(map[string]struct{})
	for _, method := range httpMethods {
		httpMethodSet[method] = struct{}{}
	}
}

func BenchmarkStringSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var test [5]byte
		_, _ = fastrand.Read(test[:])
		method := string(test[:])
		_, ok := httpMethodSet[method]
		if !ok {
			benchmarkSink = method
		}
	}
}

func BenchmarkStringSwitch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var test [5]byte
		_, _ = fastrand.Read(test[:])
		method := string(test[:])
		if !common.IsValidHttpMethod(method) {
			benchmarkSink = method
		}
	}
}
