/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/stretchr/testify/require"
)

type failedRegistrationReadConn struct {
	receiverConn
	remaining   int
	readBuffers map[*byte]struct{}
	readBlocked chan struct{}
	closedCh    chan struct{}
	closeOnce   sync.Once
	closes      atomic.Int32
}

func (c *failedRegistrationReadConn) RegisterPacketReceiver(netproxy.PacketReceiveHandler) (func(), bool) {
	return nil, false
}

func (c *failedRegistrationReadConn) ReadFrom(buf []byte) (int, netip.AddrPort, error) {
	c.readBuffers[&buf[0]] = struct{}{}
	if c.remaining > 0 {
		c.remaining--
		return copy(buf, "reply"), receiverTestFrom(), nil
	}
	close(c.readBlocked)
	<-c.closedCh
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (c *failedRegistrationReadConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closedCh) })
	return c.receiverConn.Close()
}

func TestPacketReceiverFailedRegistrationReadFromHandlerError(t *testing.T) {
	// Other tests can leave read loops finishing asynchronously. Isolate the
	// mutable release-counting seam so it cannot race those unrelated loops.
	const helperEnv = "DAE_TEST_UDP_REPLY_RELEASE"
	if os.Getenv(helperEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=10s")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "release-counting subprocess failed:\n%s", output)
		return
	}

	const packets = 33
	conn := &failedRegistrationReadConn{
		remaining:   packets,
		readBuffers: make(map[*byte]struct{}),
		readBlocked: make(chan struct{}),
		closedCh:    make(chan struct{}),
	}
	var releasesMu sync.Mutex
	releases := make(map[*byte]int)
	oldPut := putUdpEndpointReplyData
	putUdpEndpointReplyData = func(data pool.PB) {
		releasesMu.Lock()
		releases[&data[:cap(data)][0]]++
		releasesMu.Unlock()
		oldPut(data)
	}
	t.Cleanup(func() { putUdpEndpointReplyData = oldPut })
	var handled, drainReleases atomic.Int32
	ue := &UdpEndpoint{
		conn: conn,
		handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
			handled.Add(1)
			<-conn.readBlocked
			return fmt.Errorf("reply send failed")
		},
		poolKey:      UdpEndpointKey{Dst: receiverTestFrom()},
		drainRelease: func() { drainReleases.Add(1) },
	}
	require.False(t, ue.startTransportReceiver(), "registration must fall back to ReadFrom")
	readDone := make(chan struct{})
	go func() {
		ue.startReadLoop()
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("fallback sender did not close the conn and drain the read loop")
	}
	require.NoError(t, ue.Close())
	require.Equal(t, int32(1), handled.Load())
	require.Equal(t, int32(1), conn.closes.Load())
	require.Equal(t, int32(1), drainReleases.Load())
	require.Len(t, conn.readBuffers, packets+1, "queued and read-loop buffers must have exclusive ownership")
	releasesMu.Lock()
	defer releasesMu.Unlock()
	require.Len(t, releases, packets+1)
	for buf := range conn.readBuffers {
		require.Equal(t, 1, releases[buf], "each queued or still-held read buffer must be released exactly once")
	}
}

type delayedRegistrationConn struct {
	receiverConn
	delivered          chan struct{}
	returnRegistration <-chan struct{}
	release            func()
	closes             atomic.Int32
}

func (c *delayedRegistrationConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	stop, ok := c.receiverConn.RegisterPacketReceiver(handler)
	if !ok {
		return stop, ok
	}
	handler(netproxy.NewReceivedPacket([]byte("sync-register"), receiverTestFrom(), nil, c.release))
	close(c.delivered)
	<-c.returnRegistration
	return stop, true
}

func (c *delayedRegistrationConn) Close() error {
	c.closes.Add(1)
	return c.receiverConn.Close()
}

func TestPacketReceiverCloseConcurrentHandlerError(t *testing.T) {
	for _, duringRegistration := range []bool{false, true} {
		name := "registered"
		if duringRegistration {
			name = "during_registration"
		}
		t.Run(name, func(t *testing.T) {
			const packets = udpEndpointReplyQueueSize + 17
			releases := make([]atomic.Int32, packets)
			returnRegistration := make(chan struct{})
			conn := &delayedRegistrationConn{
				delivered:          make(chan struct{}),
				returnRegistration: returnRegistration,
				release:            func() { releases[0].Add(1) },
			}
			entered := make(chan struct{})
			returnHandler := make(chan struct{})
			var handled, drainReleases atomic.Int32
			ue := &UdpEndpoint{
				conn: conn,
				handler: func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error {
					if handled.Add(1) == 1 {
						close(entered)
					}
					<-returnHandler
					return fmt.Errorf("reply send failed")
				},
				poolKey:      UdpEndpointKey{Dst: receiverTestFrom()},
				drainRelease: func() { drainReleases.Add(1) },
			}
			registered := make(chan bool, 1)
			go func() { registered <- ue.startTransportReceiver() }()
			select {
			case <-conn.delivered:
			case <-time.After(time.Second):
				t.Fatal("registration did not deliver its queued reply")
			}
			if !duringRegistration {
				close(returnRegistration)
				require.True(t, <-registered)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("reply handler was not invoked")
			}
			for i := 1; i < packets; i++ {
				packet := netproxy.NewReceivedPacket([]byte{byte(i)}, receiverTestFrom(), nil, func() {
					releases[i].Add(1)
				})
				require.True(t, ue.handleReceivedPacket(packet))
			}

			closed := make(chan error, 1)
			go func() { closed <- ue.Close() }()
			require.Eventually(t, func() bool {
				ue.replyQueueMu.Lock()
				defer ue.replyQueueMu.Unlock()
				return ue.replyQueueClosed
			}, time.Second, time.Millisecond, "Close did not close the shared queue")
			select {
			case err := <-closed:
				t.Fatalf("Close returned %v before the handler finished", err)
			default:
			}
			close(returnHandler)
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(time.Second):
				if duringRegistration {
					close(returnRegistration)
				}
				t.Fatal("Close deadlocked after a queued handler error")
			}
			if duringRegistration {
				close(returnRegistration)
				require.True(t, <-registered)
			}
			require.NoError(t, ue.Close())
			require.Equal(t, int32(1), handled.Load(), "handler error must discard later replies")
			for i := range releases {
				require.Equal(t, int32(1), releases[i].Load(), "packet %d was not released exactly once", i)
			}
			require.Equal(t, int32(1), conn.closes.Load())
			require.Equal(t, int32(1), drainReleases.Load())
			require.Equal(t, 1, conn.unregisterCount())
		})
	}
}
