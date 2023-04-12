/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Sniffer struct {
	r      io.Reader
	buf    []byte
	bufAt  int
	stream bool
	readMu sync.Mutex
}

func NewStreamSniffer(r io.Reader, bufSize int) *Sniffer {
	s := &Sniffer{
		r:      r,
		buf:    make([]byte, bufSize),
		stream: true,
	}
	return s
}

func NewPacketSniffer(data []byte) *Sniffer {
	s := &Sniffer{
		buf:    data,
		stream: false,
	}
	return s
}

type sniff func() (d string, err error)

func (s *Sniffer) SniffTcp() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.stream {
		r, isConn := s.r.(net.Conn)
		if isConn {
			// Set timeout.
			r.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		n, err := r.Read(s.buf)
		if isConn {
			// Recover.
			r.SetReadDeadline(time.Time{})
		}
		s.buf = s.buf[:n]
		if err != nil {
			var netError net.Error
			if isConn && errors.As(err, &netError) && netError.Timeout() {
				goto sniff
			}
			return "", err
		}
	}
sniff:
	if len(s.buf) == 0 {
		return "", NotApplicableError
	}
	sniffs := []sniff{
		// Most sniffable traffic is TLS, thus we sniff it first.
		s.SniffTls,
		s.SniffHttp,
	}
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return d, nil
		}
		if err != NotApplicableError {
			return "", err
		}
	}
	return "", NotApplicableError
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.buf != nil && s.bufAt < len(s.buf) {
		// Read buf first.
		n = copy(p, s.buf[s.bufAt:])
		s.bufAt += n
		if s.bufAt >= len(s.buf) {
			s.buf = nil
		}
		return n, nil
	}
	if !s.stream {
		return 0, io.EOF
	}
	return s.r.Read(p)
}

func (s *Sniffer) Close() (err error) {
	return nil
}
