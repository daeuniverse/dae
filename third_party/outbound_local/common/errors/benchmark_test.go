/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// This benchmark demonstrates the performance difference between
// string matching and type-safe error checking in real-world scenarios.
package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// Real-World Scenario Benchmarks
// ============================================================================

// BenchmarkDNS_HttpClient_DirectOld demonstrates the old approach
// used in direct/dialer.go before optimization.
func BenchmarkDNS_HttpClient_DirectOld(b *testing.B) {
	// Simulate real DNS timeout error from net.Resolver
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: dial udp 127.0.0.53:53: i/o timeout")

	callbackCalled := false
	callback := func() { callbackCalled = true }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// OLD CODE (from direct/dialer.go):
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") && strings.Contains(err.Error(), "lookup") {
				callback()
			}
		}
	}

	// Prevent compiler optimization
	if !callbackCalled {
		b.Error("callback should have been called")
	}
}

// BenchmarkDNS_HttpClient_DirectNew demonstrates the optimized approach
// using type-safe error checking.
func BenchmarkDNS_HttpClient_DirectNew(b *testing.B) {
	// Simulate real DNS timeout error from net.Resolver
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: dial udp 127.0.0.53:53: i/o timeout")

	callbackCalled := false
	callback := func() { callbackCalled = true }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// NEW CODE (optimized):
		if err != nil {
			if IsDNSTimeout(err) {
				callback()
			}
		}
	}

	// Prevent compiler optimization
	if !callbackCalled {
		b.Error("callback should have been called")
	}
}

// BenchmarkStream_TUIC_ClientRingOld demonstrates the old approach
// used in tuic/client_ring.go before optimization.
func BenchmarkStream_TUIC_ClientRingOld(b *testing.B) {
	// Simulate real stream exhausted error from QUIC
	streamErr := errors.New("too many open streams")

	shouldRetry := false

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// OLD CODE (from tuic/client_ring.go):
		err := streamErr
		if strings.Contains(err.Error(), "too many open streams") ||
			errors.Is(err, errors.New("client closed")) ||
			errors.Is(err, errors.New("hold on")) {
			shouldRetry = true
		}
	}

	// Prevent compiler optimization
	if !shouldRetry {
		b.Error("should have retried")
	}
}

// BenchmarkStream_TUIC_ClientRingNew demonstrates the optimized approach
// using type-safe error checking.
func BenchmarkStream_TUIC_ClientRingNew(b *testing.B) {
	// Simulate real stream exhausted error from QUIC
	streamErr := errors.New("too many open streams")

	shouldRetry := false

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// NEW CODE (optimized):
		err := streamErr
		if ShouldRetryStreamOperation(err) {
			shouldRetry = true
		}
	}

	// Prevent compiler optimization
	if !shouldRetry {
		b.Error("should have retried")
	}
}

// BenchmarkStream_TUIC_ClientOld demonstrates the old approach
// used in tuic/client.go before optimization.
func BenchmarkStream_TUIC_ClientOld(b *testing.B) {
	// Simulate deferQuicConn error check
	streamErr := errors.New("too many open streams")
	tempErr := false

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := streamErr
		// OLD CODE (from tuic/client.go):
		if err != nil && !tempErr && !strings.Contains(err.Error(), "too many open streams") {
			// Would close connection
			_ = err
		}
	}
}

// BenchmarkStream_TUIC_ClientNew demonstrates the optimized approach
// using type-safe error checking.
func BenchmarkStream_TUIC_ClientNew(b *testing.B) {
	// Simulate deferQuicConn error check
	streamErr := errors.New("too many open streams")
	tempErr := false

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := streamErr
		// NEW CODE (optimized):
		if err != nil && !tempErr && !IsStreamExhausted(err) {
			// Would close connection
			_ = err
		}
	}
}

// ============================================================================
// Comparative Benchmarks (Side-by-Side)
// ============================================================================

// BenchmarkComparative_DNS_Check compares old vs new approach
// in a single benchmark for direct comparison.
func BenchmarkComparative_DNS_Check(b *testing.B) {
	dnsErr := fmt.Errorf("lookup example.com: i/o timeout")

	b.Run("Old_StringMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = strings.Contains(dnsErr.Error(), "i/o timeout") &&
				strings.Contains(dnsErr.Error(), "lookup")
		}
	})

	b.Run("New_TypeSafe", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = IsDNSTimeout(dnsErr)
		}
	})
}

// BenchmarkComparative_Stream_Check compares old vs new approach
// for stream error detection.
func BenchmarkComparative_Stream_Check(b *testing.B) {
	streamErr := errors.New("too many open streams")

	b.Run("Old_StringMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = strings.Contains(streamErr.Error(), "too many open streams")
		}
	})

	b.Run("New_TypeSafe", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = IsStreamExhausted(streamErr)
		}
	})
}

// BenchmarkComparative_ComplexStream_Check compares the complex
// stream retry logic used in client_ring.go.
func BenchmarkComparative_ComplexStream_Check(b *testing.B) {
	streamErr := errors.New("too many open streams")
	clientClosedErr := errors.New("client closed")
	holdOnErr := errors.New("hold on")

	b.Run("Old_ComplexStringMatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := streamErr
			// Simulate the old complex condition
			shouldRetry := strings.Contains(err.Error(), "too many open streams") ||
				errors.Is(err, clientClosedErr) ||
				errors.Is(err, holdOnErr)
			_ = shouldRetry
		}
	})

	b.Run("New_ShouldRetry", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ShouldRetryStreamOperation(streamErr)
		}
	})
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

// BenchmarkMemory_DNS_Check_Detailed measures memory allocations
// for DNS timeout checking.
func BenchmarkMemory_DNS_Check_Detailed(b *testing.B) {
	dnsErr := fmt.Errorf("lookup example.com: i/o timeout")

	b.Run("Old", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			errStr := dnsErr.Error()
			_ = strings.Contains(errStr, "i/o timeout") && strings.Contains(errStr, "lookup")
		}
	})

	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = IsDNSTimeout(dnsErr)
		}
	})
}

// BenchmarkMemory_Stream_Check_Detailed measures memory allocations
// for stream exhausted checking.
func BenchmarkMemory_Stream_Check_Detailed(b *testing.B) {
	streamErr := errors.New("too many open streams")

	b.Run("Old", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = strings.Contains(streamErr.Error(), "too many open streams")
		}
	})

	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = IsStreamExhausted(streamErr)
		}
	})
}
