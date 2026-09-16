/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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

// readResult carries the outcome of a single async stream read. It is reused
// across reads through s.readResultCh to avoid per-call channel allocation.
type readResult struct {
	n   int64
	err error
}

// snifferPool recycles *Sniffer structs across connections/packets to avoid
// per-connection struct and dataReady channel allocation.
//
// Pooling safety: a Sniffer is only returned to the pool in Close when no async
// reader goroutine is lingering (s.readerLingering is false). A lingering reader
// (only possible on the timeout path where r ignores deadlines) keeps a
// reference to the pooled bytes.Buffer; to avoid use-after-pool-put on that rare
// path, such sniffers are deliberately dropped and left for GC instead of being
// recycled.
var snifferPool = sync.Pool{
	New: func() any { return &Sniffer{} },
}

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	conn      net.Conn
	dataReady chan struct{}
	// dataReadyOnce guarantees a single close of dataReady across all
	// producers (async reader, AppendData, Sniff, Close).
	dataReadyOnce sync.Once
	dataError     error

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
	data           [][]byte
	needMore       bool
	quicNextRead   int
	quicCryptos    []*quicutils.CryptoFrameOffset
	quicPlaintexts []pool.PB
	// quicLocator is reused across SniffQuic calls to avoid allocating a new
	// LinearLocator each time. It is Reset (not reallocated) on reuse.
	quicLocator *quicutils.LinearLocator

	// Async read reuse (stream path). readResultCh is allocated lazily on the
	// first async read and reused across reads on the normal completion path
	// (recreated on timeout). readerLingering is set only on the timeout path
	// where the reader goroutine may outlive Close; such sniffers are dropped
	// instead of recycled to avoid use-after-pool-put of the bytes.Buffer.
	readResultCh    chan readResult
	readerLingering bool
}

// reset prepares s for reuse from snifferPool. All per-connection state is
// re-initialized and a fresh pooled buffer is attached.
func (s *Sniffer) reset(stream bool, r io.Reader, conn net.Conn, data []byte, timeout time.Duration) {
	s.stream = stream
	s.r = r
	s.conn = conn
	s.dataReady = make(chan struct{})
	s.dataReadyOnce = sync.Once{}
	s.dataError = nil
	s.sniffed = ""
	s.buf = pool.GetBuffer()
	s.ctxOnce = sync.Once{}
	s.closeMu = sync.Once{}
	s.ctx = nil
	s.cancel = nil
	s.deadline = time.Now().Add(timeout)
	s.data = nil
	s.needMore = false
	quicutils.ReleaseCryptoFrameOffsets(s.quicCryptos)
	s.quicNextRead = 0
	s.quicCryptos = nil
	// quicPlaintexts is deliberately NOT released here: reset() runs on pool
	// checkout, and every pooled sniffer reaches it only via Close (or
	// CompactPacketState), which already Put each plaintext and cleared the
	// slice under readMu. Releasing here as well would double-Put buffers, so
	// reset() must never be used on a sniffer that was not closed first;
	// the nil assignment is purely defensive.
	s.quicPlaintexts = nil
	// readResultCh is allocated lazily on the first async read so the common
	// deadline-sync path (production TCP) pays no channel allocation here.
	s.readResultCh = nil
	s.readerLingering = false
	if stream {
		s.buf.Grow(AssumedTlsClientHelloMaxLength)
		s.buf.Reset()
	} else {
		// Packet sniffer: always seed s.data with one entry (the buffer
		// bytes), matching the original NewPacketSniffer. AppendData appends
		// further entries; downstream replay/buffering relies on this initial
		// sentinel even when the sniffer is created with no data yet.
		if data != nil {
			_, _ = s.buf.Write(data)
		}
		s.data = [][]byte{s.buf.Bytes()}
	}
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	conn, _ := r.(net.Conn)
	s := snifferPool.Get().(*Sniffer)
	s.reset(true, r, conn, nil, timeout)
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	s := snifferPool.Get().(*Sniffer)
	s.reset(false, nil, nil, data, timeout)
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
		s.closeDataReady()
		return nil
	}
	s.closeDataReady()
	s.dataError = err

	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		// Keep behavior consistent with context timeout path in the legacy async read.
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}
	return err
}

func (s *Sniffer) readStreamOnceAsync() error {
	ctx := s.ensureAsyncContext()
	// Allocate the result channel lazily on the first async read; reuse it on
	// the normal completion path (the select below drains exactly one value)
	// and replace it on timeout where the reader may still push a stale value.
	if s.readResultCh == nil {
		s.readResultCh = make(chan readResult, 1)
	}
	ch := s.readResultCh

	// Single reader goroutine. Inlining the former outer goroutine removes one
	// closure allocation per call; the read semantics (order, timeout, error
	// propagation) are preserved exactly.
	go func() {
		n, err := s.buf.ReadFromOnce(s.r)
		ch <- readResult{n, err}
	}()

	select {
	case <-ctx.Done():
		s.dataError = ctx.Err()
		// The reader is still blocked on r and will outlive this call; mark it
		// so Close drops the struct instead of recycling it (the reader holds
		// a reference to the pooled bytes.Buffer).
		s.readerLingering = true
		// Replace the channel: the reader may still complete and push, or may
		// never push when r ignores deadlines. A fresh channel is used for the
		// next read so a stale/stuck push cannot corrupt it.
		s.readResultCh = make(chan readResult, 1)
		if s.conn != nil {
			_ = s.conn.SetReadDeadline(time.Unix(1, 0))
		}
		s.closeDataReady()
		if s.conn != nil {
			_ = s.conn.SetReadDeadline(time.Time{})
		}
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	case rr := <-ch:
		if rr.err != nil {
			s.dataError = rr.err
		}
		s.closeDataReady()
		if s.dataError != nil {
			return s.dataError
		}
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
		if err != nil && oerr != nil {
			err = fmt.Errorf("%w: %w", oerr, err)
		}
	}()
	for {
		if s.stream {
			if err := s.readStreamOnce(); err != nil {
				return "", err
			}
		} else {
			s.closeDataReady()
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
			// The previous dataReady was already closed by readStreamOnce
			// when the round's data arrived. A fresh channel is needed for
			// the next round, and its Once must be reset too: without it,
			// the consumed Once would never close the fresh channel and
			// TakeRelayPrefix would log an abnormal-sniff-state warning on
			// every connection that needed more than one read round.
			s.dataReady = make(chan struct{})
			s.dataReadyOnce = sync.Once{}
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
		s.closeDataReady()
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

// CompactPacketState releases buffered UDP sniffing payloads while keeping the
// logical sniff result intact. This is used once a packet sniffer session no
// longer needs historical datagrams for QUIC reassembly, so the session can
// stay alive as lightweight flow state instead of retaining large handshake
// buffers until TTL expiry.
func (s *Sniffer) CompactPacketState() {
	if s.stream {
		return
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.buf == nil {
		// Already closed by concurrent Close(); nothing to compact.
		return
	}

	for _, p := range s.quicPlaintexts {
		p.Put()
	}
	s.quicPlaintexts = nil
	quicutils.ReleaseCryptoFrameOffsets(s.quicCryptos)
	s.quicCryptos = nil
	s.quicNextRead = 0
	s.needMore = false

	oldBuf := s.buf
	newBuf := pool.GetBuffer()
	newBuf.Reset()
	s.buf = newBuf
	s.data = [][]byte{newBuf.Bytes()}

	if oldBuf != nil {
		pool.PutBuffer(oldBuf)
	}
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.buf == nil {
		// Closed while this reader was waiting on dataReady. The wait
		// happens outside readMu, so a concurrent Close() can win the
		// race: it holds the lock, returns the pooled buffer to the pool
		// and nils s.buf before we get here. Reading a nil buffer would
		// panic in (*bytes.Buffer).Len (nil pointer dereference).
		return 0, net.ErrClosed
	}

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

// closeDataReady closes s.dataReady exactly once across all producers
// (async reader, AppendData, Sniff, Close). It is safe to call concurrently.
func (s *Sniffer) closeDataReady() {
	s.dataReadyOnce.Do(func() { close(s.dataReady) })
}

func (s *Sniffer) Close() (err error) {
	s.closeMu.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		// Wake any reader blocked on dataReady (e.g. a packet sniffer whose
		// connection closed before any data arrived) so relayCopyLoop can
		// observe ErrClosed and exit instead of leaking the goroutine.
		s.closeDataReady()
		// Hold readMu to synchronize with CompactPacketState which also
		// touches s.buf and s.quicPlaintexts under the same lock.
		s.readMu.Lock()
		if s.buf != nil {
			if s.readerLingering {
				// The lingering async reader still holds this bytes.Buffer and
				// may write into it after Close returns (it never takes
				// readMu). Recycle neither the buffer nor the struct; dropping
				// only the struct would let the stale write corrupt the next
				// connection that checks the buffer out of the pool. GC
				// claims both once the reader exits.
				s.buf = nil
			} else {
				pool.PutBuffer(s.buf)
				s.buf = nil
			}
		}
		for _, p := range s.quicPlaintexts {
			p.Put()
		}
		s.quicPlaintexts = nil
		quicutils.ReleaseCryptoFrameOffsets(s.quicCryptos)
		s.quicCryptos = nil
		s.readMu.Unlock()
		// Recycle the struct only when no async reader goroutine is lingering.
		// A lingering reader (timeout path with no deadline support) holds a
		// reference to the pooled bytes.Buffer and could corrupt it after reuse;
		// such sniffers are dropped and left for GC instead.
		if !s.readerLingering {
			snifferPool.Put(s)
		}
	})
	return nil
}
