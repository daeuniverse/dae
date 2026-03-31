// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// NewSocks5Dialer returns a socks5 proxy netproxy.
func NewSocks5Dialer(s string, d netproxy.Dialer) (netproxy.Dialer, error) {
	return NewSocks5(s, d)
}

func (s *Socks5) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		c, err := s.dialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[socks5]: dial to %s error: %w", s.addr, err)
		}
		if _, err := s.connect(c, addr, socks.CmdConnect); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case "udp":
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		c, err := s.dialer.DialContext(ctx, tcpNetwork, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[socks5]: dial to %s error: %w", s.addr, err)
		}

		// Get the proxy addr we should dial.
		var uAddr socks.Addr
		if uAddr, err = s.connect(c, addr, socks.CmdUDPAssociate); err != nil {
			_ = c.Close()
			return nil, err
		}

		buf := pool.Get(socks.MaxAddrLen)
		defer pool.Put(buf)

		uAddress := uAddr.String()
		h, p, _ := net.SplitHostPort(uAddress)
		// if returned bind ip is unspecified
		if ip, err := netip.ParseAddr(h); err == nil && ip.IsUnspecified() {
			// indicate using conventional addr
			h, _, _ = net.SplitHostPort(s.addr)
			uAddress = net.JoinHostPort(h, p)
		}

		conn, err := s.dialer.DialContext(ctx, network, uAddress)
		if err != nil {
			return nil, fmt.Errorf("[socks5] dialudp to %s error: %w", uAddress, err)
		}
		pc, ok := conn.(netproxy.PacketConn)
		if !ok {
			return nil, fmt.Errorf("[socks5] forwarder is not transport.PacketConn")
		}

		return NewPktConn(pc, uAddress, addr, c), nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// connect takes an existing connection to a socks5 proxy server,
// and commands the server to extend that connection to target,
// which must be a canonical address with a host and port.
func (s *Socks5) connect(conn netproxy.Conn, target string, cmd byte) (addr socks.Addr, err error) {
	// the size here is just an estimate
	buf := pool.Get(socks.MaxAddrLen)
	defer pool.Put(buf)

	buf = append(buf[:0], Version)
	if len(s.user) > 0 && len(s.user) < 256 && len(s.password) < 256 {
		buf = append(buf, 2 /* num auth methods */, socks.AuthNone, socks.AuthPassword)
	} else {
		buf = append(buf, 1 /* num auth methods */, socks.AuthNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return addr, errors.New("proxy: failed to write greeting to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return addr, errors.New("proxy: failed to read greeting from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}
	if buf[0] != Version {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " has unexpected version " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] == 0xff {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " requires authentication")
	}

	if buf[1] == socks.AuthPassword {
		buf = buf[:0]
		buf = append(buf, 1 /* password protocol version */)
		buf = append(buf, uint8(len(s.user)))
		buf = append(buf, s.user...)
		buf = append(buf, uint8(len(s.password)))
		buf = append(buf, s.password...)

		if _, err := conn.Write(buf); err != nil {
			return addr, errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return addr, errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if buf[1] != 0 {
			return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " rejected username/password")
		}
	}

	buf = buf[:0]
	buf = append(buf, Version, cmd, 0 /* reserved */)
	tgtAddr, err := socks.ParseAddr(target)
	if err != nil {
		return nil, err
	}
	buf = append(buf, tgtAddr...)

	if _, err := conn.Write(buf); err != nil {
		return addr, errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	// read VER REP RSV
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return addr, errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	failure := "unknown error"
	if int(buf[1]) < len(socks.Errors) {
		failure = socks.Errors[buf[1]].Error()
		if strings.Contains(failure, "command not supported") {
			failure += " by socks5 server: " + socks.Command[cmd]
		}
	}

	if len(failure) > 0 {
		return addr, errors.New("proxy: SOCKS5 proxy at " + s.addr + " failed to connect: " + failure)
	}

	return socks.ReadAddr(conn)
}
