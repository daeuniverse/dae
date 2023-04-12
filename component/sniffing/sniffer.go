/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"io"
	"sync"
	"time"
)

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	dataReady chan struct{}
	dataError error

	// Common
	buf    []byte
	bufAt  int
	readMu sync.Mutex
}

func NewStreamSniffer(r io.Reader, bufSize int) *Sniffer {
	s := &Sniffer{
		r:         r,
		buf:       make([]byte, bufSize),
		stream:    true,
		dataReady: make(chan struct{}),
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

func sniffGroup(sniffs []sniff) (d string, err error) {
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

func (s *Sniffer) SniffTcp() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.stream {
		go func() {
			n, err := s.r.Read(s.buf)
			s.buf = s.buf[:n]
			if err != nil {
				s.dataError = err
			}
			close(s.dataReady)
		}()

		// Waiting 100ms for data.
		select {
		case <-time.After(100 * time.Millisecond):
			return "", NotApplicableError
		case <-s.dataReady:
			if s.dataError != nil {
				return "", s.dataError
			}
		}
	} else {
		close(s.dataReady)
	}

	if len(s.buf) == 0 {
		return "", NotApplicableError
	}

	return sniffGroup([]sniff{
		// Most sniffable traffic is TLS, thus we sniff it first.
		s.SniffTls,
		s.SniffHttp,
	})
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Always ready.
	close(s.dataReady)

	if len(s.buf) == 0 {
		return "", NotApplicableError
	}

	return sniffGroup([]sniff{
		s.SniffQuic,
	})
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady
	if s.dataError != nil {
		return 0, s.dataError
	}

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
