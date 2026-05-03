/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

type benchConn struct {
	reader io.Reader
	writer bytes.Buffer
}

func (c *benchConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *benchConn) Write(p []byte) (int, error)        { return c.writer.Write(p) }
func (c *benchConn) Close() error                       { return nil }
func (c *benchConn) SetDeadline(_ time.Time) error      { return nil }
func (c *benchConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *benchConn) SetWriteDeadline(_ time.Time) error { return nil }

func newBenchConn(payload []byte) *benchConn {
	return &benchConn{reader: bytes.NewReader(payload)}
}

func BenchmarkRelayCopyLoop_1KB(b *testing.B) {
	benchmarkRelayCopyLoop(b, make([]byte, 1024))
}

func BenchmarkRelayCopyLoop_32KB(b *testing.B) {
	benchmarkRelayCopyLoop(b, make([]byte, 32*1024))
}

func BenchmarkRelayCopyLoop_1MB(b *testing.B) {
	benchmarkRelayCopyLoop(b, make([]byte, 1024*1024))
}

func BenchmarkRelayCopyLoop_10MB(b *testing.B) {
	benchmarkRelayCopyLoop(b, make([]byte, 10*1024*1024))
}

func benchmarkRelayCopyLoop(b *testing.B, payload []byte) {
	buf := make([]byte, relayCopyBufferSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := newBenchConn(payload)
		dst := &benchConn{}
		_, _ = relayCopyLoop(context.Background(), dst, src, buf, noopTrafficRecord)
	}
}

func BenchmarkRelayCopyDirect_1KB(b *testing.B) {
	benchmarkRelayCopyDirect(b, make([]byte, 1024))
}

func BenchmarkRelayCopyDirect_1MB(b *testing.B) {
	benchmarkRelayCopyDirect(b, make([]byte, 1024*1024))
}

func benchmarkRelayCopyDirect(b *testing.B, payload []byte) {
	buf := make([]byte, relayCopyBufferSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := bytes.NewReader(payload)
		dst := &bytes.Buffer{}
		_, _ = relayCopyDirect(dst, src, buf, noopTrafficRecord)
	}
}

func BenchmarkDefaultRelayCopyEngine_Copy_1MB(b *testing.B) {
	payload := make([]byte, 1024*1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := newBenchConn(payload)
		dst := &benchConn{}
		_, _ = (defaultRelayCopyEngine{}).Copy(context.Background(), dst, src, noopTrafficRecord)
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := relayCopyBufferPool.Get().(*[]byte)
		relayCopyBufferPool.Put(buf)
	}
}
