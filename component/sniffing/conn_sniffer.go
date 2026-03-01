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
	spliceFailed atomic.Bool
	// skipSplice indicates splice should be skipped (incompatible protocols).
	skipSplice bool
}

// spliceIncompatiblePorts contains ports for protocols incompatible with splice(2).
// These protocols use PTY/pipes, command/response mode, or character-by-character I/O.
var spliceIncompatiblePorts = map[uint16]bool{
	// Terminal
	22: true, 23: true, 2222: true, 22222: true,
	// Mail
	25: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true,
	// File transfer
	21: true,
	// Database
	3306: true, 5432: true, 6379: true, 27017: true,
	// Other
	119: true, 194: true, 6667: true,
}

// shouldSkipSplice determines if splice should be skipped for this connection.
func shouldSkipSplice(conn net.Conn) bool {
	addr := conn.RemoteAddr()
	if addr == nil {
		return false
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		port := uint16(tcpAddr.Port)
		// Check incompatible list
		if spliceIncompatiblePorts[port] {
			return true
		}
		// Known compatible ports will try splice
		// Unknown ports will also try splice (optimistic)
		// Failure will be handled by spliceFailed flag
		return false
	}
	return false
}

func NewConnSniffer(conn net.Conn, timeout time.Duration) *ConnSniffer {
	s := &ConnSniffer{
		Conn:       conn,
		Sniffer:    NewStreamSniffer(conn, timeout),
		skipSplice: shouldSkipSplice(conn),
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

	// If splice has failed before or should be skipped, use fallback.
	if s.skipSplice || s.spliceFailed.Load() {
		return s.fallbackWriteTo(w, n)
	}

	// Try zero-copy splice.
	if spliced, spliceErr := s.trySplice(w); spliced > 0 || spliceErr != nil {
		if spliceErr != nil {
			// Splice failed - disable it for future calls on this connection.
			s.spliceFailed.Store(true)
			if spliced == 0 {
				// Complete failure before any transfer - safe to fallback
				return s.fallbackWriteTo(w, n)
			}
			// Partial success: data has been transferred but connection may be broken.
			// Return the error so caller (like SSH) can detect the issue.
			return n + spliced, spliceErr
		}
		// Complete success
		return n + spliced, nil
	}
	// Splice unavailable (not supported) - use fallback
	return s.fallbackWriteTo(w, n)
}

// trySplice attempts zero-copy splice. Returns (bytes, error) on success/partial.
// Returns (0, nil) if unavailable - caller should fallback to io.Copy.
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

	spliced, err := spliceDirect(dstFD, srcFD)
	if err != nil && spliced == 0 {
		// Complete failure before any transfer - safe to fallback
		return 0, nil
	}
	// Return both count and error (if any). For partial success, the caller
	// needs the error to detect connection issues (critical for SSH, etc).
	return spliced, err
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
	// If splice has failed before or should be skipped, use fallback.
	if s.skipSplice || s.spliceFailed.Load() {
		return io.Copy(s.Conn, r)
	}

	// Try zero-copy splice.
	if spliced, spliceErr := s.trySpliceFrom(r); spliced > 0 || spliceErr != nil {
		if spliceErr != nil {
			// Splice failed - disable it for future calls on this connection.
			s.spliceFailed.Store(true)
			if spliced == 0 {
				// Complete failure before any transfer - safe to fallback
				return io.Copy(s.Conn, r)
			}
			// Partial success: return error so caller can detect connection issue.
			return spliced, spliceErr
		}
		// Complete success
		return spliced, nil
	}
	// Splice unavailable - use fallback
	return io.Copy(s.Conn, r)
}

// trySpliceFrom attempts zero-copy splice from r to the underlying connection.
// Same semantics as trySplice.
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

	spliced, err := spliceDirect(dstFD, srcFD)
	if err != nil && spliced == 0 {
		return 0, nil
	}
	return spliced, err
}
