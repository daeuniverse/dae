//go:build linux
// +build linux

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

const relayBenchFixedTotalBytes = 8 << 20

var relayBenchPrefix = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

type relayBenchOpaqueConn struct {
	netproxy.Conn
}

type relayBenchScenario struct {
	name      string
	prefix    []byte
	wrapLeft  func(*net.TCPConn, []byte) netproxy.Conn
	wrapRight func(*net.TCPConn) netproxy.Conn
}

type relayBenchFlow struct {
	srcWriter *net.TCPConn
	dstReader *net.TCPConn
	left      netproxy.Conn
	right     netproxy.Conn
	total     int
	body      int
}

type relayBenchFlowResult struct {
	written int64
	err     error
}

func BenchmarkRelayCopyEngine_FixedTotalBytesByConcurrency(b *testing.B) {
	benchmarkRelayFixedTotalBytesByConcurrency(b, "copy_engine", relayBenchRunCopyEngine)
}

func BenchmarkRelayTCP_FixedTotalBytesByConcurrency(b *testing.B) {
	benchmarkRelayFixedTotalBytesByConcurrency(b, "relay_tcp", relayBenchRunRelayTCP)
}

func benchmarkRelayFixedTotalBytesByConcurrency(b *testing.B, group string, runner func(netproxy.Conn, netproxy.Conn) relayBenchFlowResult) {
	scenarios := []relayBenchScenario{
		{
			name:   "direct_fastpath",
			prefix: nil,
			wrapLeft: func(conn *net.TCPConn, _ []byte) netproxy.Conn {
				return netproxy.Conn(conn)
			},
			wrapRight: func(conn *net.TCPConn) netproxy.Conn {
				return netproxy.Conn(conn)
			},
		},
		{
			name:   "prefixed_gather_fastpath",
			prefix: relayBenchPrefix,
			wrapLeft: func(conn *net.TCPConn, prefix []byte) netproxy.Conn {
				return &prefixedConn{Conn: conn, prefix: append([]byte(nil), prefix...)}
			},
			wrapRight: func(conn *net.TCPConn) netproxy.Conn {
				return netproxy.Conn(conn)
			},
		},
		{
			name:   "opaque_slowpath",
			prefix: nil,
			wrapLeft: func(conn *net.TCPConn, _ []byte) netproxy.Conn {
				return relayBenchOpaqueConn{Conn: conn}
			},
			wrapRight: func(conn *net.TCPConn) netproxy.Conn {
				return netproxy.Conn(conn)
			},
		},
	}

	chunkSizes := []struct {
		name string
		size int
	}{
		{name: "mtu1500", size: 1460},
		{name: "burst16k", size: 16 << 10},
		{name: "burst64k", size: 64 << 10},
	}

	fanouts := []int{1, 4, 16, 64}

	for _, scenario := range scenarios {
		scenario := scenario
		for _, chunk := range chunkSizes {
			chunk := chunk
			for _, fanout := range fanouts {
				fanout := fanout
				b.Run(fmt.Sprintf("%s/%s/%s/fanout=%d", group, scenario.name, chunk.name, fanout), func(b *testing.B) {
					benchmarkRelayFanoutCase(b, scenario, fanout, chunk.size, runner)
				})
			}
		}
	}
}

func benchmarkRelayFanoutCase(b *testing.B, scenario relayBenchScenario, fanout int, chunkSize int, runner func(netproxy.Conn, netproxy.Conn) relayBenchFlowResult) {
	b.Helper()

	if fanout <= 0 {
		b.Fatal("fanout must be positive")
	}

	perFlowTotals := relayBenchSplitTotalBytes(relayBenchFixedTotalBytes, fanout)
	totalWrites := 0
	for _, total := range perFlowTotals {
		body := total - len(scenario.prefix)
		if body < 0 {
			b.Fatalf("flow payload budget %d is smaller than prefix %d", total, len(scenario.prefix))
		}
		totalWrites += relayBenchWriteCount(body, chunkSize)
	}

	b.ReportAllocs()
	b.SetBytes(relayBenchFixedTotalBytes)
	b.ReportMetric(float64(fanout), "flows/op")
	b.ReportMetric(float64(totalWrites), "writes/op")
	b.ReportMetric(float64(totalWrites)/float64(fanout), "writes/flow")

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		flows := make([]relayBenchFlow, 0, fanout)
		for _, total := range perFlowTotals {
			body := total - len(scenario.prefix)
			flow := relayBenchNewFlow(b, scenario, total, body)
			flows = append(flows, flow)
		}

		writeErrCh := make(chan error, fanout)
		readErrCh := make(chan relayBenchFlowResult, fanout)
		for _, flow := range flows {
			flow := flow
			go func() {
				writeErrCh <- relayBenchWriteBody(flow.srcWriter, flow.body, chunkSize)
			}()
			go func() {
				n, err := io.Copy(io.Discard, flow.dstReader)
				readErrCh <- relayBenchFlowResult{written: n, err: err}
			}()
		}

		resultCh := make(chan relayBenchFlowResult, fanout)
		var relayWG sync.WaitGroup
		relayWG.Add(fanout)

		b.StartTimer()
		for _, flow := range flows {
			flow := flow
			go func() {
				defer relayWG.Done()
				resultCh <- runner(flow.right, flow.left)
			}()
		}
		relayWG.Wait()
		b.StopTimer()

		for _, flow := range flows {
			if wc, ok := flow.right.(WriteCloser); ok {
				_ = wc.CloseWrite()
			}
		}

		for idx, flow := range flows {
			result := <-resultCh
			if result.err != nil {
				b.Fatalf("relay run failed for flow %d/%d: %v", idx+1, fanout, result.err)
			}
			if result.written > 0 && result.written != int64(flow.total) {
				b.Fatalf("unexpected copied bytes for flow %d/%d: got %d want %d", idx+1, fanout, result.written, flow.total)
			}
		}

		for idx := range flows {
			if err := <-writeErrCh; err != nil {
				b.Fatalf("writer failed for flow %d/%d: %v", idx+1, fanout, err)
			}
		}
		for idx, flow := range flows {
			result := <-readErrCh
			if result.err != nil {
				b.Fatalf("reader failed for flow %d/%d: %v", idx+1, fanout, result.err)
			}
			if result.written != int64(flow.total) {
				b.Fatalf("reader byte mismatch for flow %d/%d: got %d want %d", idx+1, fanout, result.written, flow.total)
			}
		}

		for _, flow := range flows {
			relayBenchCloseFlow(flow)
		}
	}
}

func relayBenchRunCopyEngine(dst, src netproxy.Conn) relayBenchFlowResult {
	n, err := (defaultRelayCopyEngine{}).Copy(context.Background(), dst, src)
	return relayBenchFlowResult{written: n, err: err}
}

func relayBenchRunRelayTCP(dst, src netproxy.Conn) relayBenchFlowResult {
	err := RelayTCP(src, dst)
	return relayBenchFlowResult{err: err}
}

func relayBenchNewFlow(tb testing.TB, scenario relayBenchScenario, total int, body int) relayBenchFlow {
	tb.Helper()

	srcWriter, srcRelay := tcpConnPair(tb)
	dstRelay, dstReader := tcpConnPair(tb)
	if err := dstReader.CloseWrite(); err != nil {
		_ = srcWriter.Close()
		_ = srcRelay.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
		tb.Fatalf("close dst peer write half: %v", err)
	}

	left := scenario.wrapLeft(srcRelay, scenario.prefix)
	right := scenario.wrapRight(dstRelay)

	return relayBenchFlow{
		srcWriter: srcWriter,
		dstReader: dstReader,
		left:      left,
		right:     right,
		total:     total,
		body:      body,
	}
}

func relayBenchCloseFlow(flow relayBenchFlow) {
	if flow.srcWriter != nil {
		_ = flow.srcWriter.Close()
	}
	if flow.left != nil {
		_ = flow.left.Close()
	}
	if flow.right != nil {
		_ = flow.right.Close()
	}
	if flow.dstReader != nil {
		_ = flow.dstReader.Close()
	}
}

func relayBenchSplitTotalBytes(total int, fanout int) []int {
	parts := make([]int, fanout)
	base := total / fanout
	remainder := total % fanout
	for i := range parts {
		parts[i] = base
		if i < remainder {
			parts[i]++
		}
	}
	return parts
}

func relayBenchWriteCount(total int, chunkSize int) int {
	if total <= 0 {
		return 0
	}
	return (total + chunkSize - 1) / chunkSize
}

func relayBenchWriteBody(conn *net.TCPConn, total int, chunkSize int) error {
	chunk := make([]byte, chunkSize)
	for remaining := total; remaining > 0; {
		n := chunkSize
		if remaining < n {
			n = remaining
		}
		if err := relayBenchWriteAll(conn, chunk[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return conn.CloseWrite()
}

func relayBenchWriteAll(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
