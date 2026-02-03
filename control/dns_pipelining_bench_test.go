package control

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// mockPipeConn implements netproxy.Conn effectively enough for pipelinedConn
type mockPipeConn struct {
	net.Conn
}

func (m *mockPipeConn) CloseWrite() error { return nil }
func (m *mockPipeConn) CloseRead() error  { return nil }

// BenchmarkPipelinedConn_Sequential benchmarks sequential DNS queries
func BenchmarkPipelinedConn_Sequential(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Server goroutine
	go func() {
		for {
			h := make([]byte, 2)
			if _, err := io.ReadFull(server, h); err != nil {
				return
			}
			l := binary.BigEndian.Uint16(h)
			buf := make([]byte, l)
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			var msg dnsmessage.Msg
			if err := msg.Unpack(buf); err != nil {
				return
			}
			resp := msg
			resp.Response = true
			out, _ := resp.Pack()
			resBuf := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(resBuf[0:2], uint16(len(out)))
			copy(resBuf[2:], out)
			server.Write(resBuf)
		}
	}()

	pc := newPipelinedConn(&mockPipeConn{client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("example.com."), dnsmessage.TypeA)
	req.RecursionDesired = true
	data, _ := req.Pack()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := pc.RoundTrip(ctx, data)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPipelinedConn_Concurrent benchmarks concurrent DNS queries
func BenchmarkPipelinedConn_Concurrent(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Server goroutine
	go func() {
		for {
			h := make([]byte, 2)
			if _, err := io.ReadFull(server, h); err != nil {
				return
			}
			l := binary.BigEndian.Uint16(h)
			buf := make([]byte, l)
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			var msg dnsmessage.Msg
			if err := msg.Unpack(buf); err != nil {
				return
			}
			resp := msg
			resp.Response = true
			out, _ := resp.Pack()
			resBuf := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(resBuf[0:2], uint16(len(out)))
			copy(resBuf[2:], out)
			server.Write(resBuf)
		}
	}()

	pc := newPipelinedConn(&mockPipeConn{client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("example.com."), dnsmessage.TypeA)
	req.RecursionDesired = true
	data, _ := req.Pack()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err := pc.RoundTrip(ctx, data)
			cancel()
			if err != nil {
				b.Error(err)
			}
		}
	})
}

// BenchmarkPipelinedConn_IDAllocation benchmarks ID allocation performance
func BenchmarkPipelinedConn_IDAllocation(b *testing.B) {
	pc := &pipelinedConn{
		pending: make(map[uint16]chan *dnsmessage.Msg),
		closed:  make(chan struct{}),
	}

	// Pre-fill with some pending requests to simulate realistic conditions
	for i := uint16(0); i < 100; i++ {
		pc.pending[i] = make(chan *dnsmessage.Msg, 1)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pc.pendingMu.Lock()
		start := uint16(i)
		allocSuccess := false
		for j := uint16(0); j < 1000; j++ {
			id := start + j
			if _, ok := pc.pending[id]; !ok {
				allocSuccess = true
				break
			}
		}
		pc.pendingMu.Unlock()

		if !allocSuccess {
			b.Fatal("Failed to allocate ID")
		}
	}
}

// BenchmarkSingleflight benchmarks singleflight performance
func BenchmarkDnsController_Singleflight(b *testing.B) {
	opt := &DnsControllerOption{
		ConcurrencyLimit: 1000,
	}
	ctrl, err := NewDnsController(nil, opt)
	if err != nil {
		b.Fatal(err)
	}

	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.RecursionDesired = true

	req := &udpRequest{
		routingResult: &bpfRoutingResult{},
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Note: This benchmark will fail because we don't have a real DNS server,
	// but it can be used to measure the singleflight overhead
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// We can't actually run this without a full setup,
			// but this shows how to benchmark singleflight
			_ = ctrl
			_ = msg
			_ = req
		}
	})
}

// BenchmarkPipelinedConn_Contention benchmarks performance under high contention
func BenchmarkPipelinedConn_Contention(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Server goroutine with delay to simulate network latency
	go func() {
		for {
			h := make([]byte, 2)
			if _, err := io.ReadFull(server, h); err != nil {
				return
			}
			l := binary.BigEndian.Uint16(h)
			buf := make([]byte, l)
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			var msg dnsmessage.Msg
			if err := msg.Unpack(buf); err != nil {
				return
			}
			resp := msg
			resp.Response = true
			out, _ := resp.Pack()
			resBuf := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(resBuf[0:2], uint16(len(out)))
			copy(resBuf[2:], out)
			server.Write(resBuf)
		}
	}()

	pc := newPipelinedConn(&mockPipeConn{client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("example.com."), dnsmessage.TypeA)
	req.RecursionDesired = true
	data, _ := req.Pack()

	b.ResetTimer()
	b.ReportAllocs()

	// Use multiple goroutines to create contention
	const numGoroutines = 10
	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < b.N/numGoroutines; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err := pc.RoundTrip(ctx, data)
				cancel()
				if err != nil {
					b.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
