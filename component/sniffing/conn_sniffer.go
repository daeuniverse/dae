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
	"sync/atomic"
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
	// spliceFailed tracks whether splice has failed. Once failed, use io.Copy.
	// This provides automatic transparent fallback for incompatible protocols.
	spliceFailed atomic.Bool
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

	// If splice has failed before, use fallback.
	if s.spliceFailed.Load() {
		return s.fallbackWriteTo(w, n)
	}

	// Try zero-copy splice with transparent fallback.
	// If splice fails at any point, we immediately continue with io.Copy
	// to ensure data integrity and connection stability.
	spliced, spliceErr := s.trySplice(w)
	if spliceErr != nil {
		// Splice failed - mark it and continue with fallback.
		// We've already transferred 'spliced' bytes successfully.
		s.spliceFailed.Store(true)

		// Continue transferring remaining data with io.Copy.
		// This ensures complete transparency to the application.
		copied, copyErr := io.Copy(w, s.Conn)
		total := n + spliced + copied

		// Return the first error encountered (prefer copyErr if both exist).
		if copyErr != nil {
			return total, copyErr
		}
		// If splice failed but copy succeeded, don't return splice error
		// to maintain transparency.
		return total, nil
	}

	// Splice succeeded or unavailable
	if spliced > 0 {
		// Complete success via splice
		return n + spliced, nil
	}

	// Splice unavailable (not supported) - use fallback
	return s.fallbackWriteTo(w, n)
}

// trySplice attempts zero-copy splice. Returns (bytes, nil) on success.
// Returns (0, nil) if splice is unavailable - caller should fallback to io.Copy.
// Returns (bytes, error) if splice failed after partial transfer - caller should
// continue with io.Copy to maintain transparency.
func (s *ConnSniffer) trySplice(w io.Writer) (int64, error) {
	src, ok := s.Conn.(syscallConner)
	if !ok {
		return 0, nil
	}
	dst, ok := w.(syscallConner)
	if !ok {
		return 0, nil
	}

	rawSrc, err := src.SyscallConn()
	if err != nil {
		return 0, nil
	}
	rawDst, err := dst.SyscallConn()
	if err != nil {
		return 0, nil
	}

	srcFD, ok := extractFD(rawSrc)
	if !ok {
		return 0, nil
	}
	dstFD, ok := extractFD(rawDst)
	if !ok {
		return 0, nil
	}

	// Attempt splice - will return partial bytes on failure
	return spliceDirect(dstFD, srcFD)
}

// spliceDirect performs zero-copy splice between two file descriptors.
func spliceDirect(dstFD, srcFD int) (int64, error) {
	const (
		maxSpliceSize    = 1 << 30 // 1GB
		spliceToEOFLimit = 1 << 40 // 1TB
	)
	var total int64

	for total < spliceToEOFLimit {
		remaining := spliceToEOFLimit - total
		if remaining > maxSpliceSize {
			remaining = maxSpliceSize
		}

		n, err := syscall.Splice(srcFD, nil, dstFD, nil, int(remaining), 0)
		if err != nil {
			return total, err
		}

		total += int64(n)
		if n == 0 { // EOF
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
	// If splice has failed before, use fallback.
	if s.spliceFailed.Load() {
		return io.Copy(s.Conn, r)
	}

	// Try zero-copy splice with transparent fallback.
	// If splice fails at any point, we immediately continue with io.Copy
	// to ensure data integrity and connection stability.
	spliced, spliceErr := s.trySpliceFrom(r)
	if spliceErr != nil {
		// Splice failed - mark it and continue with fallback.
		// We've already transferred 'spliced' bytes successfully.
		s.spliceFailed.Store(true)

		// Continue transferring remaining data with io.Copy.
		// This ensures complete transparency to the application.
		copied, copyErr := io.Copy(s.Conn, r)
		total := spliced + copied

		// Return the first error encountered (prefer copyErr if both exist).
		if copyErr != nil {
			return total, copyErr
		}
		// If splice failed but copy succeeded, don't return splice error
		// to maintain transparency.
		return total, nil
	}

	// Splice succeeded or unavailable
	if spliced > 0 {
		// Complete success via splice
		return spliced, nil
	}

	// Splice unavailable (not supported) - use fallback
	return io.Copy(s.Conn, r)
}

// trySpliceFrom attempts zero-copy splice from r to the underlying connection.
// Same semantics as trySplice: returns (bytes, nil) on success, (0, nil) if
// unavailable, or (bytes, error) on partial failure.
func (s *ConnSniffer) trySpliceFrom(r io.Reader) (int64, error) {
	src, ok := r.(syscallConner)
	if !ok {
		return 0, nil
	}
	dst, ok := s.Conn.(syscallConner)
	if !ok {
		return 0, nil
	}

	rawSrc, err := src.SyscallConn()
	if err != nil {
		return 0, nil
	}
	rawDst, err := dst.SyscallConn()
	if err != nil {
		return 0, nil
	}

	srcFD, ok := extractFD(rawSrc)
	if !ok {
		return 0, nil
	}
	dstFD, ok := extractFD(rawDst)
	if !ok {
		return 0, nil
	}

	// Attempt splice - will return partial bytes on failure
	return spliceDirect(dstFD, srcFD)
}
