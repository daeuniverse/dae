package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
)

var (
	SymmetricDirect  netproxy.Dialer = &lazyDirectDialer{fullcone: false}
	FullconeDirect   netproxy.Dialer = &lazyDirectDialer{fullcone: true}
	directOnce       sync.Once
	_symmetricDirect netproxy.Dialer
	_fullconeDirect  netproxy.Dialer
)

// lazyDirectDialer provides lazy initialization for direct dialers.
// It ensures InitDirectDialers is called before any dial operation.
type lazyDirectDialer struct {
	fullcone bool
}

func (d *lazyDirectDialer) ensureInit() {
	directOnce.Do(func() {
		_symmetricDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false})
		_fullconeDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true})
	})
}

func (d *lazyDirectDialer) getDialer() netproxy.Dialer {
	d.ensureInit()
	if d.fullcone {
		return _fullconeDirect
	}
	return _symmetricDirect
}

// InitDirectDialers initializes the global direct dialers with optional fallback DNS.
// If not called, dialers will be lazily initialized without fallback DNS on first use.
func InitDirectDialers(fallbackDNS string) {
	directOnce.Do(func() {
		_symmetricDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false, FallbackDNS: fallbackDNS})
		_fullconeDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true, FallbackDNS: fallbackDNS})
	})
}

func (d *lazyDirectDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.getDialer().DialContext(ctx, network, addr)
}

func (d *lazyDirectDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.getDialer().(interface {
		LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
	}); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type Option struct {
	FullCone    bool
	FallbackDNS string
}

type directDialer struct {
	tcpDialer      *net.Dialer
	tcpDialerMptcp *net.Dialer
	udpLocalAddr   *net.UDPAddr
	Option         Option
}

func NewDirectDialerLaddr(lAddr netip.Addr, option Option) netproxy.Dialer {
	var tcpLocalAddr *net.TCPAddr
	var udpLocalAddr *net.UDPAddr
	if lAddr.IsValid() {
		tcpLocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
		udpLocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
	}
	tcpDialer := &net.Dialer{LocalAddr: tcpLocalAddr}
	tcpDialerMptcp := &net.Dialer{LocalAddr: tcpLocalAddr}
	tcpDialerMptcp.SetMultipathTCP(true)
	d := &directDialer{
		tcpDialer:      tcpDialer,
		tcpDialerMptcp: tcpDialerMptcp,
		udpLocalAddr:   udpLocalAddr,
		Option:         option,
	}

	return d
}

func (d *directDialer) tryRetry(err error, addr string, callback func()) {
	host, _, _ := net.SplitHostPort(addr)
	// Check if the host is domain
	if _, e := netip.ParseAddr(host); e == nil {
		// addr is IP
		return
	}

	// addr is domain
	if err != nil {
		if err == outbounderrors.ErrDNSTimeout {
			callback()
		}
	}
}

func (d *directDialer) createResolver(mark int, fallback bool) *net.Resolver {
	if mark == 0 && !fallback {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			if mark != 0 {
				dialer.Control = func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				}
			}
			if fallback {
				return dialer.DialContext(ctx, network, d.Option.FallbackDNS)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func preferredNetwork(baseNetwork, ipVersion string) string {
	switch ipVersion {
	case "4", "6":
		return baseNetwork + ipVersion
	default:
		return baseNetwork
	}
}

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int, ipVersion string, fallback bool) (c netproxy.PacketConn, err error) {
	network := preferredNetwork("udp", ipVersion)
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialUdp(ctx, addr, mark, ipVersion, true)
			})
		}()
	}
	resolver := d.createResolver(mark, fallback)
	if mark == 0 {
		if d.Option.FullCone {
			conn, err := net.ListenUDP(network, d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr, resolver: resolver}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: d.udpLocalAddr,
				Resolver:  resolver,
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr, resolver: resolver}, nil
		}

	} else {
		var conn *net.UDPConn
		if d.Option.FullCone {
			c := net.ListenConfig{
				Control: func(network string, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				KeepAlive: 0,
			}
			laddr := ""
			if d.udpLocalAddr != nil {
				laddr = d.udpLocalAddr.String()
			}
			_conn, err := c.ListenPacket(context.Background(), network, laddr)
			if err != nil {
				return nil, err
			}
			conn = _conn.(*net.UDPConn)
		} else {
			dialer := net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				LocalAddr: d.udpLocalAddr,
				Resolver:  d.createResolver(mark, fallback),
			}
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.Option.FullCone, dialTgt: addr, resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
					Resolver: resolver,
				}
				return dialer.DialContext(ctx, network, address)
			},
		}}, nil
	}
}

func (d *directDialer) dialTcp(ctx context.Context, addr string, mark int, ipVersion string, mptcp bool, fallback bool) (c net.Conn, err error) {
	network := preferredNetwork("tcp", ipVersion)
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialTcp(ctx, addr, mark, ipVersion, mptcp, true)
			})
		}()
	}
	var dialer net.Dialer
	if mptcp {
		dialer = *d.tcpDialerMptcp
	} else {
		dialer = *d.tcpDialer
	}
	if mark != 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		}
	} else {
		dialer.Control = nil
	}
	dialer.Resolver = d.createResolver(mark, fallback)
	return dialer.DialContext(ctx, network, addr)
}

func (d *directDialer) lookupIPAddr(ctx context.Context, host string, mark int, fallback bool) ([]net.IPAddr, error) {
	resolver := d.createResolver(mark, fallback)
	if resolver == nil {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	return resolver.LookupIPAddr(ctx, host)
}

func (d *directDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	ips, err := d.lookupIPAddr(ctx, host, int(magicNetwork.Mark), false)
	if err != nil && d.Option.FallbackDNS != "" && outbounderrors.IsDNSTimeout(err) {
		return d.lookupIPAddr(ctx, host, int(magicNetwork.Mark), true)
	}
	return ips, err
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(ctx, addr, int(magicNetwork.Mark), magicNetwork.IPVersion, magicNetwork.Mptcp, false)
	case "udp":
		return d.dialUdp(ctx, addr, int(magicNetwork.Mark), magicNetwork.IPVersion, false)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
