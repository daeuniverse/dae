package control

import (
	"context"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestOutboundConnectivityMapKey(t *testing.T) {
	tests := []struct {
		name     string
		outbound uint8
		network  *dialer.NetworkType
		want     uint32
	}{
		{
			name:     "tcp4",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
			},
			want: 8,
		},
		{
			name:     "tcp6",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
			},
			want: 9,
		},
		{
			name:     "udp4",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_4,
			},
			want: 10,
		},
		{
			name:     "udp6",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_6,
			},
			want: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outboundConnectivityMapKey(tt.outbound, tt.network); got != tt.want {
				t.Fatalf("outboundConnectivityMapKey() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDialerAliveTransitionCallback_IgnoresDnsUdpTransitions(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	conn := &scriptedPacketConn{
		reads:   make(chan scriptedPacketRead),
		closeCh: make(chan struct{}),
	}
	d := newTestProxyEndpointDialer("hysteria2", "proxy.example:443", conn)
	key := UdpEndpointKey{Src: netip.MustParseAddrPort("127.0.0.1:25001")}
	ue := &UdpEndpoint{
		conn:                conn,
		NatTimeout:          DefaultNatTimeout,
		Dialer:              d,
		handler:             func(_ *UdpEndpoint, _ []byte, _ netip.AddrPort) error { return nil },
		poolRef:             DefaultUdpEndpointPool,
		poolKey:             key,
		endpointNetworkType: dialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4},
	}

	shard := DefaultUdpEndpointPool.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
	DefaultUdpEndpointPool.registerEndpoint(ue)

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	core := &controlPlaneCore{
		log:    logger,
		closed: context.Background(),
	}

	core.dialerAliveTransitionCallback(d)(&dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
		IsDns:     true,
	}, false)

	if got, ok := DefaultUdpEndpointPool.Get(key); !ok || got != ue {
		t.Fatal("expected DNS UDP transition to leave generic UDP endpoint pooled")
	}
	if got := conn.closeCalls.Load(); got != 0 {
		t.Fatalf("close calls = %d, want 0", got)
	}
}
