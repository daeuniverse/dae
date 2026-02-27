package control

import (
	"net/netip"
	"sync"
	"time"
)

const (
	quicReassemblyShards = 16
	quicSessionTimeout   = 500 * time.Millisecond
)

type QuicReassemblyPool struct {
	shards  [quicReassemblyShards]quicShard
	bufPool sync.Pool
}

type quicShard struct {
	sync.Mutex
	sessions map[netip.AddrPort]*quicSession
}

type quicSession struct {
	buf      []byte
	lastSeen time.Time
}

func NewQuicReassemblyPool() *QuicReassemblyPool {
	p := &QuicReassemblyPool{
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 2048)
				return &b
			},
		},
	}
	for i := range p.shards {
		p.shards[i].sessions = make(map[netip.AddrPort]*quicSession, 64)
	}
	return p
}

func (p *QuicReassemblyPool) shardIdx(key netip.AddrPort) int {
	h := key.Addr().As16()
	v := uint64(h[0]) ^ uint64(h[1])<<8 ^ uint64(h[2])<<16 ^ uint64(h[3])<<24
	v ^= uint64(key.Port())
	return int(v % quicReassemblyShards)
}

func (p *QuicReassemblyPool) Emit(key netip.AddrPort, data []byte, task func([]byte)) {
	idx := p.shardIdx(key)
	shard := &p.shards[idx]

	shard.Lock()

	now := time.Now()
	session, ok := shard.sessions[key]
	if !ok {
		bufPtr := p.bufPool.Get().(*[]byte)
		session = &quicSession{
			buf:      (*bufPtr)[:0],
			lastSeen: now,
		}
		shard.sessions[key] = session
	}

	session.buf = append(session.buf, data...)
	session.lastSeen = now
	accumulated := session.buf

	task(accumulated)

	shard.Unlock()
}

func (p *QuicReassemblyPool) EmitWithDone(key netip.AddrPort, data []byte, task func([]byte) bool) {
	idx := p.shardIdx(key)
	shard := &p.shards[idx]

	shard.Lock()

	now := time.Now()
	session, ok := shard.sessions[key]
	if !ok {
		bufPtr := p.bufPool.Get().(*[]byte)
		session = &quicSession{
			buf:      (*bufPtr)[:0],
			lastSeen: now,
		}
		shard.sessions[key] = session
	}

	session.buf = append(session.buf, data...)
	session.lastSeen = now

	if task(session.buf) {
		delete(shard.sessions, key)
		session.buf = session.buf[:0]
		p.bufPool.Put(&session.buf)
	}

	shard.Unlock()
}

func (p *QuicReassemblyPool) CleanupExpired() {
	now := time.Now()
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for key, session := range shard.sessions {
			if now.Sub(session.lastSeen) > quicSessionTimeout {
				delete(shard.sessions, key)
				session.buf = session.buf[:0]
				p.bufPool.Put(&session.buf)
			}
		}
		shard.Unlock()
	}
}

var DefaultQuicReassemblyPool = NewQuicReassemblyPool()

func InitQuicReassemblyCleaner(interval time.Duration) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				DefaultQuicReassemblyPool.CleanupExpired()
			}
		}
	}()
	return func() { close(done) }
}
