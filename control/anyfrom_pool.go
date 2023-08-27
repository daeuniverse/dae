package control

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/softwind/pool"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	EnableBatchThreshold = 10
)

type packets struct {
	mu   sync.Mutex
	list *list.List
}
type packetsPair struct {
	*net.UDPAddr
	*packets
}
type Anyfrom struct {
	writeTimes uint32

	*net.UDPConn
	is4            bool
	pc4            *ipv4.PacketConn
	pc6            *ipv6.PacketConn
	deadlineTimer  *time.Timer
	ttl            time.Duration
	muMAddrPackets sync.Mutex
	mAddrPackets   map[netip.AddrPort]*packets
	ticker         *time.Ticker
}

func (a *Anyfrom) handleBatch() {
	buffer := pool.GetBuffer()
	defer pool.PutBuffer(buffer)
	for range a.ticker.C {
		a.muMAddrPackets.Lock()
		var lists = make([]*packetsPair, 0, len(a.mAddrPackets))
		for addr, packets := range a.mAddrPackets {
			if packets == nil || packets.list.Len() == 0 {
				delete(a.mAddrPackets, addr)
				continue
			}
			lists = append(lists, &packetsPair{
				AddrPort: addr,
				packets:  packets,
			})
		}
		a.muMAddrPackets.Unlock()
		for _, pair := range lists {
			pc := ipv6.NewPacketConn(a.UDPConn)
			pc.WriteBatch([]ipv6.Message{{
				Buffers: [][]byte{},
				Addr:    pair.UDPAddr,
			}})
			ipv6.Message
		}
	}
}
func (a *Anyfrom) afterWrite(err error) {
	times := atomic.AddUint32(&a.writeTimes, 1)
	if times == EnableBatchThreshold {
		go a.handleBatch()
	}
	a.RefreshTtl()
}
func (a *Anyfrom) RefreshTtl() {
	a.deadlineTimer.Reset(a.ttl)
}
func (a *Anyfrom) ShouldUseBatch() bool {
	return a.writeTimes >= EnableBatchThreshold
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
	defer a.afterWrite(err)
	if a.ShouldUseBatch() {
		return a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDP(b, oob, addr)
}
func (a *Anyfrom) WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n int, oobn int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		return a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(oob, uint16(len(b))), addr)
	}
	return a.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}
func (a *Anyfrom) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr.(*net.UDPAddr))
		return n, err
	}
	return a.UDPConn.WriteTo(b, addr)
}
func (a *Anyfrom) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDP(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
	return a.UDPConn.WriteToUDP(b, addr)
}
func (a *Anyfrom) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	defer a.afterWrite(err)
	if a.SupportGso(len(b)) {
		n, _, err = a.UDPConn.WriteMsgUDPAddrPort(b, appendUDPSegmentSizeMsg(nil, uint16(len(b))), addr)
		return n, err
	}
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

func (p *AnyfromPool) GetOrCreate(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, isNew bool, err error) {
	strLAddr := lAddr.String()
	p.mu.RLock()
	af, ok := p.pool[strLAddr]
	if !ok {
		p.mu.RUnlock()
		p.mu.Lock()
		defer p.mu.Unlock()
		if af, ok = p.pool[strLAddr]; ok {
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
		pc, err := d.ListenPacket(context.Background(), "udp", strLAddr)
		if err != nil {
			return nil, true, err
		}
		uConn := pc.(*net.UDPConn)
		af = &Anyfrom{
			writeTimes:     0,
			UDPConn:        uConn,
			is4:            lAddr.Addr().Is4(),
			pc4:            nil,
			pc6:            nil,
			deadlineTimer:  nil,
			ttl:            ttl,
			muMAddrPackets: sync.Mutex{},
			mAddrPackets:   make(map[netip.AddrPort]*packets, 4),
			ticker:         &time.Ticker{},
		}
		af.deadlineTimer = time.AfterFunc(ttl, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			_af := p.pool[strLAddr]
			if _af == af {
				delete(p.pool, strLAddr)
				af.Close()
			}
		})
		p.pool[strLAddr] = af
		return af, true, nil
	} else {
		af.RefreshTtl()
		p.mu.RUnlock()
		return af, false, nil
	}
}
