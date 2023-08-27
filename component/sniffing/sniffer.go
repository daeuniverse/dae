/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/softwind/pool"
)

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	dataReady chan struct{}
	dataError error

	// Common
	buf      *bytes.Buffer
	readMu   sync.Mutex
	needMore bool
	ctx      context.Context
	cancel   func()

	// Quic
	quicCryptos []*quicutils.CryptoFrameOffset
}

func NewStreamSniffer(r io.Reader, bufSize int, timeout time.Duration) *Sniffer {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &Sniffer{
		stream:    true,
		r:         r,
		buf:       pool.GetBuffer(),
		dataReady: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	buffer := pool.GetBuffer()
	buffer.Write(data)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &Sniffer{
		stream:    false,
		r:         nil,
		buf:       buffer,
		dataReady: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return d, nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.stream {
		go func() {
			// Read once.
			s.buf.Reset()
			s.buf.Grow(max(0, 4096-s.buf.Available()))
			n, err := s.r.Read(s.buf.AvailableBuffer())
			if err != nil {
				s.dataError = err
			}
			s.buf.Truncate(n)
			close(s.dataReady)
		}()

		// Waiting 100ms for data.
		select {
		case <-s.dataReady:
			if s.dataError != nil {
				return "", s.dataError
			}
		case <-s.ctx.Done():
			return "", ErrNotApplicable
		}
	} else {
		close(s.dataReady)
	}

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	return sniffGroup(
		// Most sniffable traffic is TLS, thus we sniff it first.
		s.SniffTls,
		s.SniffHttp,
	)
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Always ready.
	close(s.dataReady)

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	s.buf.Write(data)
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.dataError != nil {
		n, _ = s.buf.Read(p)
		return n, s.dataError
	}

	if s.buf.Len() > 0 {
		// Read buf first.
		return s.buf.Read(p)
	}
	if !s.stream {
		return 0, io.EOF
	}
	return s.r.Read(p)
}

func (s *Sniffer) Close() (err error) {
	select {
	case <-s.ctx.Done():
	default:
		s.cancel()
		pool.PutBuffer(s.buf)
	}
	return nil
}
