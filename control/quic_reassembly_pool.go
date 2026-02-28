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

// shardIdx computes the shard index for a given key using a hash function
// with good avalanche properties for both IPv4 and IPv6 addresses.
// Uses FNV-1a-like mixing for uniform distribution across shards.
func (p *QuicReassemblyPool) shardIdx(key netip.AddrPort) int {
	// Use AsSlice() which returns 4 bytes for IPv4 and 16 bytes for IPv6
	// (unlike As16() which always returns 16 bytes with IPv4-mapped prefix)
	addrBytes := key.Addr().AsSlice()

	// FNV-1a inspired hash with good avalanche properties
	// This ensures uniform distribution even for IPs with similar prefixes
	const (
		fnvOffset64 = 14695981039346656037
		fnvPrime64  = 1099511628211
	)
	h := uint64(fnvOffset64)
	for _, b := range addrBytes {
		h ^= uint64(b)
		h *= fnvPrime64
	}

	// Mix in port number
	h ^= uint64(key.Port())
	h *= fnvPrime64

	return int(h % quicReassemblyShards)
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

	// Deep copy buffer before releasing lock to:
	// 1. Avoid sync.Pool data races (buffer may be reused after Put)
	// 2. Allow task to execute outside critical section
	accumulated := make([]byte, len(session.buf))
	copy(accumulated, session.buf)

	shard.Unlock()

	// Execute task outside lock to avoid blocking other packets
	task(accumulated)
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

	// Deep copy buffer before releasing lock
	accumulated := make([]byte, len(session.buf))
	copy(accumulated, session.buf)

	shard.Unlock()

	// Execute task outside lock
	done := task(accumulated)

	if done {
		shard.Lock()
		// Re-check session identity to handle concurrent modifications
		// Only delete if it's still the same session object we had before
		if current, exists := shard.sessions[key]; exists && current == session {
			delete(shard.sessions, key)
			session.buf = session.buf[:0]
			p.bufPool.Put(&session.buf)
		}
		shard.Unlock()
	}
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
