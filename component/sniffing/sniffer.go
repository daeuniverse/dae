/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"github.com/mzz2017/softwind/pool"
	"io"
)

type Sniffer struct {
	r      io.Reader
	buf    []byte
	bufAt  int
	stream bool
}

func NewStreamSniffer(r io.Reader, bufSize int) *Sniffer {
	s := &Sniffer{
		r:      r,
		buf:    pool.Get(bufSize),
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
	if s.stream {
		n, err := s.r.Read(s.buf)
		if err != nil {
			return "", err
		}
		s.buf = s.buf[:n]
	}
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
	if s.buf != nil && s.bufAt < len(s.buf) {
		// Read buf first.
		n = copy(p, s.buf[s.bufAt:])
		s.bufAt += n
		if s.bufAt >= len(s.buf) {
			if s.stream {
				pool.Put(s.buf)
			}
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
	// DO NOT use pool.Put() here because Close() may not interrupt the reading, which will modify the value of the pool buffer.
	return nil
}
