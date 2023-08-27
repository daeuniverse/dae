package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type Anyfrom struct {
	*net.UDPConn
	deadlineTimer *time.Timer
	ttl           time.Duration
}

func (a *Anyfrom) RefreshTtl() {
	a.deadlineTimer.Reset(a.ttl)
}
func (a *Anyfrom) ReadFrom(b []byte) (int, net.Addr, error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFrom(b)
}
func (a *Anyfrom) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDP(b)
}
func (a *Anyfrom) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadFromUDPAddrPort(b)
}
func (a *Anyfrom) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDP(b, oob)
}
func (a *Anyfrom) ReadMsgUDPAddrPort(b []byte, oob []byte) (n int, oobn int, flags int, addr netip.AddrPort, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.ReadMsgUDPAddrPort(b, oob)
}
func (a *Anyfrom) SyscallConn() (syscall.RawConn, error) {
	defer a.RefreshTtl()
	return a.UDPConn.SyscallConn()

}
func (a *Anyfrom) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.WriteMsgUDP(b, oob, addr)

}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	defer a.RefreshTtl()
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)

}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer a.RefreshTtl()
	return a.UDPConn.WriteTo(b, addr)

}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	defer a.RefreshTtl()
	return a.UDPConn.WriteToUDP(b, addr)

}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	defer a.RefreshTtl()
	return a.UDPConn.WriteToUDPAddrPort(b, addr)
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool map[string]*Anyfrom
	mu   sync.RWMutex
}

var DefaultAnyfromPool = NewAnyfromPool()

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{
		pool: make(map[string]*Anyfrom, 64),
		mu:   sync.RWMutex{},
	}
}

func (p *AnyfromPool) GetOrCreate(lAddr string, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	p.mu.RLock()
	af, ok := p.pool[lAddr]
	if !ok {
		p.mu.RUnlock()
		p.mu.Lock()
		defer p.mu.Unlock()
		if af, ok = p.pool[lAddr]; ok {
			return af, false, nil
		}
		// Create an Anyfrom.
		isNew = true
		d := net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				return dialer.TransparentControl(c)
			},
			KeepAlive: 0,
		}
		pc, err := d.ListenPacket(context.Background(), "udp", lAddr)
		if err != nil {
			return nil, true, err
		}
		af = &Anyfrom{
			UDPConn:       pc.(*net.UDPConn),
			deadlineTimer: nil,
			ttl:           ttl,
		}
		af.deadlineTimer = time.AfterFunc(ttl, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			_af := p.pool[lAddr]
			if _af == af {
				delete(p.pool, lAddr)
				af.Close()
			}
		})
		p.pool[lAddr] = af
		return af, true, nil
	} else {
		af.RefreshTtl()
		p.mu.RUnlock()
		return af, false, nil
	}
}
