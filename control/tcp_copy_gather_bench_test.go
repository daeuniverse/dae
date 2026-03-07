//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	bufferredconn "github.com/daeuniverse/outbound/pkg/bufferred_conn"
)

type gatherWriteBenchMultiSegmentConn struct {
	net.Conn
	segments [][]byte
}

type gatherWriteBenchWrappedDstConn struct {
	netproxy.Conn
}

type gatherWritePrefixBenchSource struct {
	benchNoopConn
	prefix []byte
}

func (s *gatherWritePrefixBenchSource) TakeRelayPrefix() []byte {
	return s.prefix
}

type gatherWriteSegmentBenchSource struct {
	benchNoopConn
	segments [][]byte
}

func (s *gatherWriteSegmentBenchSource) TakeRelaySegments() [][]byte {
	return s.segments
}

type benchNoopConn struct{}

func (benchNoopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchNoopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (benchNoopConn) Close() error                     { return nil }
func (benchNoopConn) SetDeadline(time.Time) error      { return nil }
func (benchNoopConn) SetReadDeadline(time.Time) error  { return nil }
func (benchNoopConn) SetWriteDeadline(time.Time) error { return nil }

func (c *gatherWriteBenchMultiSegmentConn) Read(p []byte) (int, error) {
	for len(c.segments) > 0 {
		if len(c.segments[0]) == 0 {
			c.segments = c.segments[1:]
			continue
		}
		n := copy(p, c.segments[0])
		c.segments[0] = c.segments[0][n:]
		if len(c.segments[0]) == 0 {
			c.segments = c.segments[1:]
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *gatherWriteBenchMultiSegmentConn) UnderlyingConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

func (c *gatherWriteBenchMultiSegmentConn) TakeRelaySegments() [][]byte {
	if c == nil || len(c.segments) == 0 {
		return nil
	}
	segs := c.segments
	c.segments = nil
	return segs
}

func (c *gatherWriteBenchMultiSegmentConn) CopyRelayRemainder(dst io.Writer, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, c.Conn, buf)
}

func BenchmarkRelayGatherWrite_PrefixedConn(b *testing.B) {
	benchmarkRelayGatherWrite(b, gatherWriteBenchOptions{
		name:   "prefixed",
		prefix: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		makeSrc: func(conn *net.TCPConn, prefix []byte) netproxy.Conn {
			return &prefixedConn{
				Conn:   conn,
				prefix: append([]byte(nil), prefix...),
			}
		},
	})
}

func BenchmarkRelayGatherWrite_MultiSegmentSource(b *testing.B) {
	benchmarkRelayGatherWrite(b, gatherWriteBenchOptions{
		name:   "multi_segment_src",
		prefix: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: dae\r\n\r\n"),
		makeSrc: func(conn *net.TCPConn, prefix []byte) netproxy.Conn {
			splits := []int{4, 14, 33, len(prefix)}
			segments := make([][]byte, 0, len(splits))
			start := 0
			for _, end := range splits {
				if end > len(prefix) {
					end = len(prefix)
				}
				if end <= start {
					continue
				}
				segments = append(segments, append([]byte(nil), prefix[start:end]...))
				start = end
			}
			return &gatherWriteBenchMultiSegmentConn{Conn: conn, segments: segments}
		},
	})
}

func BenchmarkRelayGatherWrite_MultiSegmentSourceWrappedDestination(b *testing.B) {
	benchmarkRelayGatherWrite(b, gatherWriteBenchOptions{
		name:   "multi_segment_wrapped_dst",
		prefix: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: dae\r\n\r\n"),
		makeSrc: func(conn *net.TCPConn, prefix []byte) netproxy.Conn {
			splits := []int{4, 14, 33, len(prefix)}
			segments := make([][]byte, 0, len(splits))
			start := 0
			for _, end := range splits {
				if end > len(prefix) {
					end = len(prefix)
				}
				if end <= start {
					continue
				}
				segments = append(segments, append([]byte(nil), prefix[start:end]...))
				start = end
			}
			return &gatherWriteBenchMultiSegmentConn{Conn: conn, segments: segments}
		},
		wrapDst: func(conn *net.TCPConn) netproxy.Conn {
			return &gatherWriteBenchWrappedDstConn{Conn: conn}
		},
	})
}

func BenchmarkRelayGatherWrite_ConnSniffer(b *testing.B) {
	benchmarkRelayGatherWrite(b, gatherWriteBenchOptions{
		name:        "sniffer",
		prefix:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		writePrefix: true,
		makeSrc: func(conn *net.TCPConn, _ []byte) netproxy.Conn {
			snifferConn := sniffing.NewConnSniffer(conn, 200*time.Millisecond)
			if _, err := snifferConn.SniffTcp(); err != nil && !sniffing.IsSniffingError(err) {
				b.Fatalf("sniff failed: %v", err)
			}
			return snifferConn
		},
		closeSrc: func(conn netproxy.Conn) error {
			return conn.Close()
		},
	})
}

func BenchmarkRelayGatherWrite_FakeNetConnDestination(b *testing.B) {
	benchmarkRelayGatherWrite(b, gatherWriteBenchOptions{
		name:   "fake_net_dst",
		prefix: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		makeSrc: func(conn *net.TCPConn, prefix []byte) netproxy.Conn {
			return &prefixedConn{
				Conn:   conn,
				prefix: append([]byte(nil), prefix...),
			}
		},
		wrapDst: func(conn *net.TCPConn) netproxy.Conn {
			return &netproxy.FakeNetConn{
				Conn:  conn,
				LAddr: conn.LocalAddr(),
				RAddr: conn.RemoteAddr(),
			}
		},
	})
}

func BenchmarkRelayGatherWrite_BufferedConnSource(b *testing.B) {
	payloadSizes := []struct {
		name string
		size int
	}{
		{name: "mtu1500", size: 1500},
		{name: "burst16k", size: 16 << 10},
		{name: "burst64k", size: 64 << 10},
	}

	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	for _, payloadSize := range payloadSizes {
		payloadSize := payloadSize
		b.Run("buffered_src/"+payloadSize.name+"/gather", func(b *testing.B) {
			relayGatherWriteEnabled = true
			defer func() { relayGatherWriteEnabled = true }()
			runRelayBufferedConnBenchmark(b, prefix, payloadSize.size)
		})
		b.Run("buffered_src/"+payloadSize.name+"/stable", func(b *testing.B) {
			relayGatherWriteEnabled = false
			defer func() { relayGatherWriteEnabled = true }()
			runRelayBufferedConnBenchmark(b, prefix, payloadSize.size)
		})
	}
}

func BenchmarkRelayGatherSegmentAssembly_PrefixSource(b *testing.B) {
	src := &gatherWritePrefixBenchSource{prefix: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")}
	body := make([]byte, 1400)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var sourceScratch [relayGatherInlineSegmentCap][]byte
		segments := relayTakeSourceSegments(src, &sourceScratch)
		var writeScratch [relayGatherInlineSegmentCap + 1][]byte
		_ = relayBuildWriteSegments(segments, body, &writeScratch)
	}
}

func BenchmarkRelayGatherSegmentAssembly_MultiSegmentSource(b *testing.B) {
	src := &gatherWriteSegmentBenchSource{segments: [][]byte{
		[]byte("GET "),
		[]byte("/ HTTP/1.1\r\nHost: "),
		[]byte("example.com\r\n\r\n"),
	}}
	body := make([]byte, 1400)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var sourceScratch [relayGatherInlineSegmentCap][]byte
		segments := relayTakeSourceSegments(src, &sourceScratch)
		var writeScratch [relayGatherInlineSegmentCap + 1][]byte
		_ = relayBuildWriteSegments(segments, body, &writeScratch)
	}
}

type gatherWriteBenchOptions struct {
	name        string
	prefix      []byte
	writePrefix bool
	makeSrc     func(conn *net.TCPConn, prefix []byte) netproxy.Conn
	closeSrc    func(conn netproxy.Conn) error
	wrapDst     func(conn *net.TCPConn) netproxy.Conn
}

func benchmarkRelayGatherWrite(b *testing.B, opts gatherWriteBenchOptions) {
	payloadSizes := []struct {
		name string
		size int
	}{
		{name: "mtu1500", size: 1500},
		{name: "burst16k", size: 16 << 10},
		{name: "burst64k", size: 64 << 10},
	}

	for _, payloadSize := range payloadSizes {
		payloadSize := payloadSize
		b.Run(opts.name+"/"+payloadSize.name+"/gather", func(b *testing.B) {
			relayGatherWriteEnabled = true
			defer func() { relayGatherWriteEnabled = true }()
			runRelayGatherWriteBenchmark(b, opts, payloadSize.size)
		})
		b.Run(opts.name+"/"+payloadSize.name+"/stable", func(b *testing.B) {
			relayGatherWriteEnabled = false
			defer func() { relayGatherWriteEnabled = true }()
			runRelayGatherWriteBenchmark(b, opts, payloadSize.size)
		})
	}
}

func runRelayGatherWriteBenchmark(b *testing.B, opts gatherWriteBenchOptions, payloadSize int) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	totalBytes := int64(len(opts.prefix) + len(payload))

	b.ReportAllocs()
	b.SetBytes(totalBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		srcWriter, srcRelay := tcpConnPair(b)
		dstRelay, dstReader := tcpConnPair(b)
		srcConn := opts.makeSrc(srcRelay, opts.prefix)
		dstConn := netproxy.Conn(dstRelay)
		if opts.wrapDst != nil {
			dstConn = opts.wrapDst(dstRelay)
		}

		var wg sync.WaitGroup
		wg.Add(2)

		writeErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			var err error
			if opts.writePrefix && len(opts.prefix) > 0 {
				_, err = srcWriter.Write(opts.prefix)
			}
			if err == nil {
				_, err = srcWriter.Write(payload)
			}
			if err == nil {
				err = srcWriter.CloseWrite()
			}
			writeErrCh <- err
		}()

		readErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			_, err := io.Copy(io.Discard, dstReader)
			readErrCh <- err
		}()

		b.StartTimer()
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstConn, srcConn)
		b.StopTimer()
		if opts.closeSrc != nil {
			_ = opts.closeSrc(srcConn)
		} else {
			_ = srcRelay.Close()
		}
		if err != nil {
			b.Fatalf("copy failed: %v", err)
		}
		if n != totalBytes {
			b.Fatalf("unexpected copied bytes: got %d want %d", n, totalBytes)
		}

		_ = dstRelay.CloseWrite()
		wg.Wait()

		if err := <-writeErrCh; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-readErrCh; err != nil {
			b.Fatalf("reader failed: %v", err)
		}

		_ = srcWriter.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}

func runRelayBufferedConnBenchmark(b *testing.B, prefix []byte, payloadSize int) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	totalBytes := int64(len(prefix) + len(payload))

	b.ReportAllocs()
	b.SetBytes(totalBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		srcWriter, srcRelay := tcpConnPair(b)
		dstRelay, dstReader := tcpConnPair(b)
		srcConn := bufferredconn.NewBufferedConnSize(srcRelay, len(prefix)+len(payload))

		var wg sync.WaitGroup
		wg.Add(2)

		writeErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			_, err := srcWriter.Write(prefix)
			if err == nil {
				_, err = srcWriter.Write(payload)
			}
			if err == nil {
				err = srcWriter.CloseWrite()
			}
			writeErrCh <- err
		}()

		if _, err := srcConn.Peek(len(prefix)); err != nil {
			b.Fatalf("prefetch failed: %v", err)
		}

		readErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			_, err := io.Copy(io.Discard, dstReader)
			readErrCh <- err
		}()

		b.StartTimer()
		n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dstRelay, srcConn)
		b.StopTimer()
		_ = srcConn.Close()
		if err != nil {
			b.Fatalf("copy failed: %v", err)
		}
		if n != totalBytes {
			b.Fatalf("unexpected copied bytes: got %d want %d", n, totalBytes)
		}

		_ = dstRelay.CloseWrite()
		wg.Wait()

		if err := <-writeErrCh; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-readErrCh; err != nil {
			b.Fatalf("reader failed: %v", err)
		}

		_ = srcWriter.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}

func tcpConnPair(tb testing.TB) (*net.TCPConn, *net.TCPConn) {
	tb.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}

	accepted := make(chan *net.TCPConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			errCh <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		_ = ln.Close()
		tb.Fatal(err)
	}

	var server *net.TCPConn
	select {
	case err := <-errCh:
		_ = client.Close()
		_ = ln.Close()
		tb.Fatal(err)
	case server = <-accepted:
	}
	_ = ln.Close()
	return client, server
}
