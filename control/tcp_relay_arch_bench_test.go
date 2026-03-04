//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

func BenchmarkRelayAdaptiveCopy_Direct(b *testing.B) {
	payload := make([]byte, 2<<20)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		var wg sync.WaitGroup
		wg.Add(2)

		writeErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			_, err := srcWriter.Write(payload)
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

		n, err := relayAdaptiveCopy(context.Background(), netproxy.Conn(dstRelay), netproxy.Conn(srcRelay))
		if err != nil {
			b.Fatalf("relayAdaptiveCopy failed: %v", err)
		}
		if n != int64(len(payload)) {
			b.Fatalf("bytes relayed mismatch: got %d want %d", n, len(payload))
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
		_ = srcRelay.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}

func BenchmarkRelayAdaptiveCopy_ConnSniffer(b *testing.B) {
	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	payload := make([]byte, 2<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	expected := int64(len(prefix) + len(payload))

	b.ReportAllocs()
	b.SetBytes(expected)

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		snifferConn := sniffing.NewConnSniffer(srcRelay, 200*time.Millisecond)

		writeErrCh := make(chan error, 1)
		go func() {
			_, err := srcWriter.Write(prefix)
			if err == nil {
				_, err = srcWriter.Write(payload)
			}
			if err == nil {
				err = srcWriter.CloseWrite()
			}
			writeErrCh <- err
		}()

		_, sniffErr := snifferConn.SniffTcp()
		if sniffErr != nil && !sniffing.IsSniffingError(sniffErr) {
			b.Fatalf("sniff failed: %v", sniffErr)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		readErrCh := make(chan error, 1)
		go func() {
			defer wg.Done()
			_, err := io.Copy(io.Discard, dstReader)
			readErrCh <- err
		}()

		n, err := relayAdaptiveCopy(context.Background(), netproxy.Conn(dstRelay), netproxy.Conn(snifferConn))
		if err != nil {
			b.Fatalf("relayAdaptiveCopy failed: %v", err)
		}
		if n != expected {
			b.Fatalf("bytes relayed mismatch: got %d want %d", n, expected)
		}

		_ = dstRelay.CloseWrite()
		wg.Wait()

		if err := <-writeErrCh; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-readErrCh; err != nil {
			b.Fatalf("reader failed: %v", err)
		}

		_ = snifferConn.Close()
		_ = srcWriter.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}
