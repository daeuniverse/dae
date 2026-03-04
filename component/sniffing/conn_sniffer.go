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

	"github.com/daeuniverse/outbound/netproxy"
)

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

// WriteTo implements io.WriterTo.
//
// Called by io.Copy when ConnSniffer is the source (client → server direction).
// Its sole purpose is to flush the sniff buffer (TLS ClientHello etc.) before
// handing the remainder of the stream to a plain io.Copy.
//
// Data flow: ConnSniffer (client) → remote proxy/server
func (s *ConnSniffer) WriteTo(w io.Writer) (n int64, err error) {
	// Flush buffered sniff data (e.g. TLS ClientHello already read).
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

	// Upgrade to zero-copy relay when both ends expose file descriptors.
	if srcConn, ok := s.Conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		if spliced, usedSplice, spliceErr := netproxy.SpliceTo(w, srcConn); usedSplice {
			return n + spliced, spliceErr
		}
	}

	// Fallback: forward the rest of the stream in userspace.
	copied, err := io.Copy(w, s.Conn)
	return n + copied, err
}

// ReadFrom implements io.ReaderFrom.
//
// Called by io.Copy when ConnSniffer is the destination (server → client
// direction).  Bypasses the read buffer and writes directly to the underlying
// connection via a plain io.Copy.
//
// Data flow: remote proxy/server → ConnSniffer (client)
func (s *ConnSniffer) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(s.Conn, r)
}
