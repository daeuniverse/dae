/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const hy2ModelReceiveQueueSize = 1024

type hy2SimulationPacket struct {
	data []byte
	from netip.AddrPort
}

// hy2SimulationConn models the Hysteria2 UDP receive path:
// messages are fed into a fixed-size queue and dropped when the queue is full.
type hy2SimulationConn struct {
	receiveCh chan hy2SimulationPacket
	closeCh   chan struct{}
	readStart chan struct{}

	sealOnce      sync.Once
	startReadOnce sync.Once

	fedPackets     atomic.Int64
	droppedPackets atomic.Int64
	readPackets    atomic.Int64
}

func newHy2SimulationConn(readStartsBlocked bool) *hy2SimulationConn {
	conn := &hy2SimulationConn{
		receiveCh: make(chan hy2SimulationPacket, hy2ModelReceiveQueueSize),
		closeCh:   make(chan struct{}),
		readStart: make(chan struct{}),
	}
	if !readStartsBlocked {
		conn.StartReading()
	}
	return conn
}

func (c *hy2SimulationConn) StartReading() {
	c.startReadOnce.Do(func() {
		close(c.readStart)
	})
}

func (c *hy2SimulationConn) Feed(data []byte, from netip.AddrPort) {
	c.fedPackets.Add(1)
	packetCopy := append([]byte(nil), data...)
	select {
	case c.receiveCh <- hy2SimulationPacket{data: packetCopy, from: from}:
	default:
		c.droppedPackets.Add(1)
	}
}

func (c *hy2SimulationConn) Seal() {
	c.sealOnce.Do(func() {
		close(c.receiveCh)
	})
}

func (c *hy2SimulationConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *hy2SimulationConn) Write(_ []byte) (int, error) {
	return 0, nil
}

func (c *hy2SimulationConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case <-c.readStart:
	}
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case packet, ok := <-c.receiveCh:
		if !ok {
			return 0, netip.AddrPort{}, io.EOF
		}
		copy(p, packet.data)
		c.readPackets.Add(1)
		return len(packet.data), packet.from, nil
	}
}

func (c *hy2SimulationConn) WriteTo(b []byte, _ string) (int, error) {
	return len(b), nil
}

func (c *hy2SimulationConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

func (c *hy2SimulationConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *hy2SimulationConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *hy2SimulationConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type hy2BoundaryMode string

const (
	hy2BoundaryModeMainSync     hy2BoundaryMode = "main-sync"
	hy2BoundaryModeDaeLossy     hy2BoundaryMode = "dae-lossy-reply-queue"
	hy2BoundaryModeBackpressure hy2BoundaryMode = "dae-backpressure-reply-queue"
)

type hy2BoundarySimulationResult struct {
	mode hy2BoundaryMode

	totalFed   int
	hy2Dropped int
	read       int
	handled    int
	daeDropped int
	elapsed    time.Duration
}

func runHy2BoundarySimulation(t *testing.T, mode hy2BoundaryMode, totalPackets int, producerGap, handlerDelay time.Duration, prebufferBeforeDrain bool) hy2BoundarySimulationResult {
	t.Helper()

	// Some scenarios model a burst that has already filled HY2's receive queue
	// before dae gets CPU time. Hold ReadFrom behind an explicit gate there so the
	// test does not accidentally depend on goroutine scheduling.
	conn := newHy2SimulationConn(prebufferBeforeDrain)
	replySrc := netip.MustParseAddrPort("203.0.113.10:3478")
	start := time.Now()

	var (
		handledCount atomic.Int64
		daeDropped   atomic.Int64
	)

	done := make(chan struct{})
	switch mode {
	case hy2BoundaryModeMainSync:
		go func() {
			defer close(done)
			runHy2MainSyncReadLoop(conn, handlerDelay, &handledCount)
		}()
	case hy2BoundaryModeDaeLossy:
		go func() {
			defer close(done)
			runHy2LossyReadLoop(conn, handlerDelay, &handledCount, &daeDropped)
		}()
	case hy2BoundaryModeBackpressure:
		ue := &UdpEndpoint{
			conn:       conn,
			NatTimeout: QuicNatTimeout,
			handler: func(_ *UdpEndpoint, _ []byte, from netip.AddrPort) error {
				if from != replySrc {
					t.Fatalf("handler from = %v, want %v", from, replySrc)
				}
				handledCount.Add(1)
				time.Sleep(handlerDelay)
				return nil
			},
		}
		ue.hasReply.Store(true)
		go func() {
			defer close(done)
			ue.start()
		}()
	default:
		t.Fatalf("unknown simulation mode %q", mode)
	}

	if !prebufferBeforeDrain {
		conn.StartReading()
	}
	feedHy2SimulationPackets(conn, totalPackets, replySrc, producerGap)
	conn.Seal()
	if prebufferBeforeDrain {
		conn.StartReading()
	}

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out waiting for simulation mode %q to finish", mode)
	}

	return hy2BoundarySimulationResult{
		mode:       mode,
		totalFed:   int(conn.fedPackets.Load()),
		hy2Dropped: int(conn.droppedPackets.Load()),
		read:       int(conn.readPackets.Load()),
		handled:    int(handledCount.Load()),
		daeDropped: int(daeDropped.Load()),
		elapsed:    time.Since(start),
	}
}

func feedHy2SimulationPackets(conn *hy2SimulationConn, totalPackets int, from netip.AddrPort, producerGap time.Duration) {
	next := time.Now()
	for i := 0; i < totalPackets; i++ {
		conn.Feed([]byte{byte(i >> 8), byte(i)}, from)
		if producerGap <= 0 {
			continue
		}
		next = next.Add(producerGap)
		for time.Now().Before(next) {
			runtime.Gosched()
		}
	}
}

func runHy2MainSyncReadLoop(conn *hy2SimulationConn, handlerDelay time.Duration, handledCount *atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		if _, _, err := conn.ReadFrom(buf); err != nil {
			return
		}
		handledCount.Add(1)
		time.Sleep(handlerDelay)
	}
}

func runHy2LossyReadLoop(conn *hy2SimulationConn, handlerDelay time.Duration, handledCount *atomic.Int64, daeDropped *atomic.Int64) {
	type queuedReply struct {
		data []byte
		from netip.AddrPort
	}

	replyCh := make(chan queuedReply, udpEndpointReplyQueueSize)
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for range replyCh {
			handledCount.Add(1)
			time.Sleep(handlerDelay)
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			close(replyCh)
			<-senderDone
			return
		}

		packetCopy := append([]byte(nil), buf[:n]...)
		select {
		case replyCh <- queuedReply{data: packetCopy, from: from}:
		default:
			select {
			case <-replyCh:
				daeDropped.Add(1)
			default:
			}
			select {
			case replyCh <- queuedReply{data: packetCopy, from: from}:
			default:
				daeDropped.Add(1)
			}
		}
	}
}

func logHy2BoundarySimulationResult(t *testing.T, result hy2BoundarySimulationResult) {
	t.Helper()
	t.Logf(
		"%s: fed=%d hy2_dropped=%d read=%d handled=%d dae_dropped=%d elapsed=%s",
		result.mode,
		result.totalFed,
		result.hy2Dropped,
		result.read,
		result.handled,
		result.daeDropped,
		result.elapsed,
	)
}

func TestHy2BoundarySimulation_PreBufferedBurst(t *testing.T) {
	const (
		totalPackets = 1200
		handlerDelay = 1 * time.Millisecond
	)

	mainResult := runHy2BoundarySimulation(t, hy2BoundaryModeMainSync, totalPackets, 0, handlerDelay, true)
	lossyResult := runHy2BoundarySimulation(t, hy2BoundaryModeDaeLossy, totalPackets, 0, handlerDelay, true)
	backpressureResult := runHy2BoundarySimulation(t, hy2BoundaryModeBackpressure, totalPackets, 0, handlerDelay, true)

	logHy2BoundarySimulationResult(t, mainResult)
	logHy2BoundarySimulationResult(t, lossyResult)
	logHy2BoundarySimulationResult(t, backpressureResult)

	if mainResult.hy2Dropped == 0 {
		t.Fatalf("pre-buffered burst should already overflow hy2 before dae drains; got hy2_dropped=0")
	}
	if lossyResult.hy2Dropped != mainResult.hy2Dropped {
		t.Fatalf("lossy hy2_dropped=%d, want %d", lossyResult.hy2Dropped, mainResult.hy2Dropped)
	}
	if backpressureResult.hy2Dropped != mainResult.hy2Dropped {
		t.Fatalf("backpressure hy2_dropped=%d, want %d", backpressureResult.hy2Dropped, mainResult.hy2Dropped)
	}
	if lossyResult.daeDropped == 0 {
		t.Fatalf("lossy reply queue should still drop inside dae after hy2 pre-buffering; got dae_dropped=0")
	}
	if backpressureResult.daeDropped != 0 {
		t.Fatalf("backpressure path must not drop inside dae; got dae_dropped=%d", backpressureResult.daeDropped)
	}
}

func TestHy2BoundarySimulation_ReceiveQueuePressure(t *testing.T) {
	const (
		handlerDelay = 1 * time.Millisecond
		producerGap  = 100 * time.Microsecond
		totalPackets = 1200
	)

	mainResult := runHy2BoundarySimulation(t, hy2BoundaryModeMainSync, totalPackets, producerGap, handlerDelay, false)
	lossyResult := runHy2BoundarySimulation(t, hy2BoundaryModeDaeLossy, totalPackets, producerGap, handlerDelay, false)
	backpressureResult := runHy2BoundarySimulation(t, hy2BoundaryModeBackpressure, totalPackets, producerGap, handlerDelay, false)

	logHy2BoundarySimulationResult(t, mainResult)
	logHy2BoundarySimulationResult(t, lossyResult)
	logHy2BoundarySimulationResult(t, backpressureResult)

	if mainResult.hy2Dropped == 0 {
		t.Fatalf("main-sync should overflow hy2 queue under pressure; got hy2_dropped=0")
	}
	if lossyResult.hy2Dropped != 0 {
		t.Fatalf("lossy reply queue should drain hy2 fast enough here; got hy2_dropped=%d", lossyResult.hy2Dropped)
	}
	if lossyResult.daeDropped == 0 {
		t.Fatalf("lossy reply queue should drop inside dae under pressure; got dae_dropped=0")
	}
	if backpressureResult.hy2Dropped != 0 {
		t.Fatalf("backpressure path should absorb this burst without hy2 drops; got hy2_dropped=%d", backpressureResult.hy2Dropped)
	}
	if backpressureResult.daeDropped != 0 {
		t.Fatalf("backpressure path must not drop inside dae; got dae_dropped=%d", backpressureResult.daeDropped)
	}
	if backpressureResult.handled != totalPackets {
		t.Fatalf("backpressure path handled=%d, want %d", backpressureResult.handled, totalPackets)
	}
	if mainResult.handled >= backpressureResult.handled {
		t.Fatalf("main-sync handled=%d, want less than backpressure handled=%d", mainResult.handled, backpressureResult.handled)
	}
	if lossyResult.handled >= backpressureResult.handled {
		t.Fatalf("lossy reply queue handled=%d, want less than backpressure handled=%d", lossyResult.handled, backpressureResult.handled)
	}
}

func TestHy2BoundarySimulation_TotalBufferLimit(t *testing.T) {
	const (
		handlerDelay = 1 * time.Millisecond
		producerGap  = 100 * time.Microsecond
		totalPackets = 1800
	)

	mainResult := runHy2BoundarySimulation(t, hy2BoundaryModeMainSync, totalPackets, producerGap, handlerDelay, false)
	lossyResult := runHy2BoundarySimulation(t, hy2BoundaryModeDaeLossy, totalPackets, producerGap, handlerDelay, false)
	backpressureResult := runHy2BoundarySimulation(t, hy2BoundaryModeBackpressure, totalPackets, producerGap, handlerDelay, false)

	logHy2BoundarySimulationResult(t, mainResult)
	logHy2BoundarySimulationResult(t, lossyResult)
	logHy2BoundarySimulationResult(t, backpressureResult)

	if mainResult.hy2Dropped == 0 {
		t.Fatalf("main-sync should overflow hy2 queue under this burst; got hy2_dropped=0")
	}
	if lossyResult.daeDropped == 0 {
		t.Fatalf("lossy reply queue should drop inside dae under this burst; got dae_dropped=0")
	}
	if backpressureResult.daeDropped != 0 {
		t.Fatalf("backpressure path must not drop inside dae; got dae_dropped=%d", backpressureResult.daeDropped)
	}
	if backpressureResult.hy2Dropped == 0 {
		t.Fatalf("backpressure path should eventually push pressure back to hy2 once all buffers fill; got hy2_dropped=0")
	}
	if backpressureResult.handled != totalPackets-backpressureResult.hy2Dropped {
		t.Fatalf(
			"backpressure handled=%d, want %d",
			backpressureResult.handled,
			totalPackets-backpressureResult.hy2Dropped,
		)
	}
	if backpressureResult.handled <= mainResult.handled {
		t.Fatalf("backpressure handled=%d, want greater than main-sync handled=%d", backpressureResult.handled, mainResult.handled)
	}
}
