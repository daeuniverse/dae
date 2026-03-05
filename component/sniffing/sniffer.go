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
	sniffed string
	buf     *bytes.Buffer
	readMu  sync.Mutex
	ctx     context.Context
	cancel  func()

	// Packet
	data           [][]byte
	packetStarts   []int
	needMore       bool
	quicNextRead   int
	quicCryptos    []*quicutils.CryptoFrameOffset
	quicPlaintexts []pool.PB
}

const (
	quicInitialSearchMaxPackets = 8
	quicInitialSearchMaxBytes   = 12 * 1024
)

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		stream: false,
		r:      nil,
		buf:    buffer,
		data:   [][]byte{buffer.Bytes()},
		packetStarts: []int{
			0,
		},
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
	if deadline, ok := s.ctx.Deadline(); ok {
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("%w: %w", errReadDeadlineUnsupported, err)
		}
		defer func() {
			// Best effort restore: sniff deadline must not leak into relay phase.
			_ = s.conn.SetReadDeadline(time.Time{})
		}()
	}

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
	go func() {
		// Read once.
		_, err := s.buf.ReadFromOnce(s.r)
		if err != nil {
			s.dataError = err
		}
		close(s.dataReady)
	}()

	select {
	case <-s.dataReady:
		if s.dataError != nil {
			return s.dataError
		}
	case <-s.ctx.Done():
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
			if off, ok := s.findQuicInitialPacketStart(); ok {
				s.quicNextRead = off
			} else {
				s.needMore = true
				return "", ErrNotApplicable
			}
		}
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	s.needMore = false
	ori := s.buf.Len()
	s.buf.Write(data)
	s.packetStarts = append(s.packetStarts, ori)
	s.data = append(s.data, s.buf.Bytes()[ori:])
}

func (s *Sniffer) findQuicInitialPacketStart() (int, bool) {
	if len(s.packetStarts) == 0 {
		return 0, false
	}
	buf := s.buf.Bytes()
	limitStart := len(buf) - quicInitialSearchMaxBytes
	if limitStart < 0 {
		limitStart = 0
	}
	pktBudget := quicInitialSearchMaxPackets

	for i := len(s.packetStarts) - 1; i >= 0; i-- {
		start := s.packetStarts[i]
		if start < s.quicNextRead || start < limitStart {
			break
		}
		if pktBudget <= 0 {
			break
		}
		pktBudget--
		if IsLikelyQuicInitialPacket(buf[start:]) {
			return start, true
		}
	}
	return 0, false
}

func (s *Sniffer) Data() [][]byte {
	return s.data
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
		if s.buf != nil {
			pool.PutBuffer(s.buf)
			s.buf = nil
		}
		for _, p := range s.quicPlaintexts {
			p.Put()
		}
		s.quicPlaintexts = nil
	}
	return nil
}
