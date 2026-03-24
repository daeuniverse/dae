/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
)

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	conn      net.Conn
	dataReady chan struct{}
	dataError error

	// Common
	sniffed  string
	buf      *bytes.Buffer
	readMu   sync.RWMutex
	ctxOnce  sync.Once
	closeMu  sync.Once
	ctx      context.Context
	cancel   func()
	deadline time.Time

	// Packet
	data             [][]byte
	needMore         bool
	quicNextRead     int
	quicCryptos      []*quicutils.CryptoFrameOffset
	quicPlaintexts   []pool.PB
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	buffer := pool.GetBuffer()
	buffer.Grow(AssumedTlsClientHelloMaxLength)
	buffer.Reset()
	conn, _ := r.(net.Conn)
	s := &Sniffer{
		stream:    true,
		r:         r,
		conn:      conn,
		buf:       buffer,
		dataReady: make(chan struct{}),
		deadline:  time.Now().Add(timeout),
	}
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	buffer := pool.GetBuffer()
	_, _ = buffer.Write(data)
	s := &Sniffer{
		stream:    false,
		r:         nil,
		buf:       buffer,
		data:      [][]byte{buffer.Bytes()},
		dataReady: make(chan struct{}),
		deadline:  time.Now().Add(timeout),
	}
	return s
}

func (s *Sniffer) ensureAsyncContext() context.Context {
	s.ctxOnce.Do(func() {
		s.ctx, s.cancel = context.WithDeadline(context.Background(), s.deadline)
	})
	return s.ctx
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return NormalizeDomain(d), nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

var errReadDeadlineUnsupported = errors.New("read deadline unsupported")

func (s *Sniffer) readStreamOnce() error {
	s.dataError = nil

	if s.conn != nil {
		if err := s.readStreamOnceWithReadDeadline(); err == nil {
			return nil
		} else if !errors.Is(err, errReadDeadlineUnsupported) {
			return err
		}
	}
	return s.readStreamOnceAsync()
}

func (s *Sniffer) readStreamOnceWithReadDeadline() error {
	if err := s.conn.SetReadDeadline(s.deadline); err != nil {
		return fmt.Errorf("%w: %w", errReadDeadlineUnsupported, err)
	}
	defer func() {
		// Best effort restore: sniff deadline must not leak into relay phase.
		_ = s.conn.SetReadDeadline(time.Time{})
	}()

	_, err := s.buf.ReadFromOnce(s.conn)
	if err == nil {
		close(s.dataReady)
		return nil
	}
	close(s.dataReady)
	s.dataError = err

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Keep behavior consistent with context timeout path in the legacy async read.
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}
	return err
}

func (s *Sniffer) readStreamOnceAsync() error {
	ctx := s.ensureAsyncContext()
	ready := s.dataReady
	go func() {
		defer close(ready)
		// Read once.
		_, err := s.buf.ReadFromOnce(s.r)
		if err != nil {
			s.dataError = err
		}
	}()

	select {
	case <-ready:
		if s.dataError != nil {
			return s.dataError
		}
	case <-ctx.Done():
		// If read is still pending, we must unblock it.
		if s.conn != nil {
			_ = s.conn.SetReadDeadline(time.Unix(1, 0))
			<-ready
			_ = s.conn.SetReadDeadline(time.Time{})
		}
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}
	return nil
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var oerr error
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", oerr, err)
		}
	}()
	for {
		if s.stream {
			if err := s.readStreamOnce(); err != nil {
				return "", err
			}
		} else {
			close(s.dataReady)
		}

		if s.buf.Len() == 0 {
			return "", ErrNotApplicable
		}

		d, err = sniffGroup(
			// Most sniffable traffic is TLS, thus we sniff it first.
			s.SniffTls,
			s.SniffHttp,
		)
		if errors.Is(err, ErrNeedMore) {
			oerr = err
			s.dataReady = make(chan struct{})
			continue
		}
		return d, err
	}
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Always ready.
	select {
	case <-s.dataReady:
	default:
		close(s.dataReady)
	}

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	if len(s.quicCryptos) == 0 {
		nextBlock := s.buf.Bytes()[s.quicNextRead:]
		if !IsLikelyQuicInitialPacket(nextBlock) {
			return "", ErrNotApplicable
		}
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	s.needMore = false
	ori := s.buf.Len()
	_, _ = s.buf.Write(data)
	s.data = append(s.data, s.buf.Bytes()[ori:])
}

func (s *Sniffer) Data() [][]byte {
	return s.data
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.RLock()
	defer s.readMu.RUnlock()

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
	s.closeMu.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.buf != nil {
			pool.PutBuffer(s.buf)
			s.buf = nil
		}
		for _, p := range s.quicPlaintexts {
			p.Put()
		}
		s.quicPlaintexts = nil
	})
	return nil
}
