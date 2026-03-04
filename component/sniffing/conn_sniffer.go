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
	"sync"
	"time"
)

const relayBufSize = 32 << 10 // 32 KB, matches control.relayCopyBufferSize

var relayBufPool = sync.Pool{
	New: func() any {
		return make([]byte, relayBufSize)
	},
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

// WriteTo implements io.WriterTo.
//
// Called by io.Copy when ConnSniffer is the source (client → server direction).
// Flushes the sniff buffer (TLS ClientHello etc.) then forwards the remainder
// of the stream via a plain io.Copy.
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

	// Reuse relay buffer to reduce per-connection heap churn.
	buf := relayBufPool.Get().([]byte)
	defer relayBufPool.Put(buf)
	copied, err := io.CopyBuffer(w, s.Conn, buf)
	return n + copied, err
}

// ReadFrom implements io.ReaderFrom.
//
// Called by io.Copy when ConnSniffer is the destination (server → client
// direction).  Bypasses the read buffer and writes directly to the underlying
// connection.
//
// We intentionally avoid io.Copy(s.Conn, r) here: net.TCPConn implements
// io.ReaderFrom, and its ReadFrom calls genericReadFrom which internally does
// io.Copy with a nil buf → make([]byte, 32768) heap allocation per connection.
// copyDirect uses an explicit caller-provided buffer and skips both WriterTo and ReaderFrom
// interface delegation, preventing that hidden allocation.
//
// Data flow: remote proxy/server → ConnSniffer (client)
func (s *ConnSniffer) ReadFrom(r io.Reader) (int64, error) {
	buf := relayBufPool.Get().([]byte)
	defer relayBufPool.Put(buf)
	return copyDirect(s.Conn, r, buf)
}

// copyDirect copies from src to dst using the provided buf without delegating
// to io.WriterTo or io.ReaderFrom interfaces. This prevents stdlib wrappers
// (e.g. net.TCPConn.ReadFrom) from silently heap-allocating their own buffers.
func copyDirect(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			return
		}
	}
}
