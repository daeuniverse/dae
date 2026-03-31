package direct

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/juicity"
	"github.com/olicesx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDirectPacketConnConcurrentWriteInitializesCachedTargetSafely(t *testing.T) {
	t.Helper()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = client.Close() }()

	oldResolveUDPAddr := resolveUDPAddr
	resolveUDPAddr = func(_ *net.Resolver, _ string) (*net.UDPAddr, error) {
		return server.LocalAddr().(*net.UDPAddr), nil
	}
	defer func() {
		resolveUDPAddr = oldResolveUDPAddr
	}()

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "example.com:53",
		resolver: net.DefaultResolver,
	}

	const writers = 8
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Errorf("Write returned error: %v", err)
			}
		}()
	}

	for i := 0; i < writers; i++ {
		buf := make([]byte, 16)
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("ReadFromUDP #%d: %v", i, err)
		}
		if got := string(buf[:n]); got != "ping" {
			t.Fatalf("unexpected payload #%d: got %q want %q", i, got, "ping")
		}
	}

	wg.Wait()

	cachedValue := conn.cachedDialTgt.Load()
	cachedAddrPort, ok := cachedValue.(netip.AddrPort)
	if !ok || !cachedAddrPort.IsValid() {
		t.Fatal("cachedDialTgt was not initialized")
	}
}

func TestFakeNetPacketConn(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		c, err := SymmetricDirect.DialContext(context.TODO(), "udp", "223.5.5.5:53")
		require.NoError(t, err)
		fc := netproxy.NewFakeNetPacketConn(c.(netproxy.PacketConn), nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.True(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
	t.Run("negative", func(t *testing.T) {
		c := (interface{})(&juicity.PacketConn{})
		fc := netproxy.NewFakeNetPacketConn(c.(netproxy.PacketConn), nil, nil)
		_, ok := fc.(quic.OOBCapablePacketConn)
		require.False(t, ok)
		_, ok = fc.(net.PacketConn)
		require.True(t, ok)
	})
}
