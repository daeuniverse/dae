/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// syscallConner is the interface implemented by connections that expose
// their underlying file descriptor via SyscallConn().
// Defined at package scope to avoid repeating the inline type in WriteTo and ReadFrom.
type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

type ConnSniffer struct {
	net.Conn
	*Sniffer
}

func NewConnSniffer(conn net.Conn, timeout time.Duration) *ConnSniffer {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	return s
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) Close() (err error) {
	var errs []string
	if err = s.Sniffer.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err = s.Conn.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// extractFD extracts the raw file descriptor from a SyscallConn.
// Returns the fd and true on success, or 0 and false on failure.
func extractFD(raw syscall.RawConn) (int, bool) {
	var fd int
	err := raw.Control(func(f uintptr) { fd = int(f) })
	return fd, err == nil
}

// WriteTo implements io.WriterTo for zero-copy splice optimization.
//
// This is called by io.Copy when ConnSniffer is the source (client -> server direction).
// It handles the buffered data first, then attempts zero-copy splice for the rest.
//
// Data flow: ConnSniffer (client) -> remote (server)
func (s *ConnSniffer) WriteTo(w io.Writer) (n int64, err error) {
	// First, drain any buffered data from the sniffer
	// This is the TLS ClientHello or other initial data that was sniffed
	if s.Sniffer != nil {
		s.Sniffer.readMu.Lock()
		if s.Sniffer.buf.Len() > 0 {
			n, err = s.Sniffer.buf.WriteTo(w)
			s.Sniffer.readMu.Unlock()
			if err != nil {
				return n, err
			}
		} else {
			s.Sniffer.readMu.Unlock()
		}
	}

	// Now attempt zero-copy splice for the remaining data
	// Check if the underlying connection and destination support SyscallConn
	srcConnI, srcOk := s.Conn.(syscallConner)
	if !srcOk {
		return s.fallbackWriteTo(w, n)
	}
	dstConnI, dstOk := w.(syscallConner)
	if !dstOk {
		return s.fallbackWriteTo(w, n)
	}

	rawSrc, err := srcConnI.SyscallConn()
	if err != nil {
		return s.fallbackWriteTo(w, n)
	}
	rawDst, err := dstConnI.SyscallConn()
	if err != nil {
		return s.fallbackWriteTo(w, n)
	}

	srcFD, ok := extractFD(rawSrc)
	if !ok {
		return s.fallbackWriteTo(w, n)
	}
	dstFD, ok := extractFD(rawDst)
	if !ok {
		return s.fallbackWriteTo(w, n)
	}

	// Perform zero-copy splice for the remaining data
	spliced, spliceErr := spliceDirect(dstFD, srcFD)
	if spliceErr != nil {
		return s.fallbackWriteTo(w, n)
	}
	return n + spliced, nil
}

// spliceDirect performs zero-copy splice between two file descriptors.
// This is the low-level implementation that directly calls syscall.Splice.
func spliceDirect(dstFD, srcFD int) (int64, error) {
	const (
		// maxSpliceSize is the maximum size for a single splice(2) syscall.
		maxSpliceSize = 1 << 30 // 1GB
		// spliceToEOFLimit is a large limit for "transfer until EOF".
		// 1TB is far larger than any realistic TCP connection will transfer.
		spliceToEOFLimit = 1 << 40 // 1TB, effectively unlimited
	)
	var total int64

	for total < spliceToEOFLimit {
		remaining := spliceToEOFLimit - total
		if remaining > maxSpliceSize {
			remaining = maxSpliceSize
		}

		// Use splice to transfer data directly in kernel space
		n, err := syscall.Splice(srcFD, nil, dstFD, nil, int(remaining), 0)
		if err != nil {
			return total, err
		}

		total += int64(n)

		// EOF reached
		if n == 0 {
			break
		}
	}

	return total, nil
}

// fallbackWriteTo performs standard read/write copy when splice is unavailable.
// n is the number of bytes already written (from buffered data).
func (s *ConnSniffer) fallbackWriteTo(w io.Writer, n int64) (int64, error) {
	// Read directly from the underlying connection, bypassing Sniffer
	// since we've already drained the buffer. Use io.Copy for efficient copying.
	copied, err := io.Copy(w, s.Conn)
	return n + copied, err
}

// ReadFrom implements io.ReaderFrom for zero-copy splice optimization.
//
// This is called by io.Copy when ConnSniffer is the destination (server -> client direction).
// It bypasses the read buffer and writes directly to the underlying connection.
//
// Data flow: remote (server) -> ConnSniffer (client)
func (s *ConnSniffer) ReadFrom(r io.Reader) (n int64, err error) {
	// For server -> client direction, we don't need the read buffer
	// (which is only for sniffing client -> server data).
	// Write directly to the underlying connection.

	// Check if source supports SyscallConn for zero-copy splice
	srcConnI, srcOk := r.(syscallConner)
	dstConnI, dstOk := s.Conn.(syscallConner)
	if !srcOk || !dstOk {
		return io.Copy(s.Conn, r)
	}

	rawSrc, err := srcConnI.SyscallConn()
	if err != nil {
		return io.Copy(s.Conn, r)
	}
	rawDst, err := dstConnI.SyscallConn()
	if err != nil {
		return io.Copy(s.Conn, r)
	}

	srcFD, ok := extractFD(rawSrc)
	if !ok {
		return io.Copy(s.Conn, r)
	}
	dstFD, ok := extractFD(rawDst)
	if !ok {
		return io.Copy(s.Conn, r)
	}

	// Perform zero-copy splice
	spliced, spliceErr := spliceDirect(dstFD, srcFD)
	if spliceErr != nil {
		return io.Copy(s.Conn, r)
	}
	return spliced, nil
}
