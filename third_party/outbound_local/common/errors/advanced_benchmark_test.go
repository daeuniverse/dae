/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package errors

import (
	"errors"
	"fmt"
	"testing"
)

// ============================================================================
// Benchmark: Direct Comparison vs Type Assertion vs String Matching
// ============================================================================

func BenchmarkMethod_DirectComparison(b *testing.B) {
	err := ErrStreamExhausted

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err == ErrStreamExhausted
	}
}

func BenchmarkMethod_TypeAssertion(b *testing.B) {
	err := &DNSError{Err: errors.New("timeout"), IsTimeout: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dnsErr *DNSError
		_ = errors.As(err, &dnsErr) && dnsErr.IsTimeout
	}
}

func BenchmarkMethod_StringMatching(b *testing.B) {
	err := errors.New("lookup example.com: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errStr := err.Error()
		_ = contains(errStr, "i/o timeout") && contains(errStr, "lookup")
	}
}

// ============================================================================
// Benchmark: Hybrid Approach
// ============================================================================

func BenchmarkHybrid_SentinelPath(b *testing.B) {
	// Test the fast path: sentinel error
	err := ErrDNSTimeout

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutHybrid(err)
	}
}

func BenchmarkHybrid_CustomTypePath(b *testing.B) {
	// Test the medium path: custom error type
	err := &DNSError{Err: errors.New("timeout"), IsTimeout: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutHybrid(err)
	}
}

func BenchmarkHybrid_StringPath(b *testing.B) {
	// Test the slow path: string matching
	err := errors.New("lookup example.com: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutHybrid(err)
	}
}

// ============================================================================
// Benchmark: Bit Flags
// ============================================================================

func BenchmarkBitFlags_HasFlag(b *testing.B) {
	err := NewDNSTimeoutFlagged(errors.New("timeout"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var flaggedErr *FlaggedError
		if errors.As(err, &flaggedErr) {
			_ = flaggedErr.HasFlag(FlagTimeout)
		}
	}
}

func BenchmarkBitFlags_IsTimeout(b *testing.B) {
	err := NewDNSTimeoutFlagged(errors.New("timeout"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutWithFlags(err)
	}
}

// ============================================================================
// Benchmark: Interface Methods
// ============================================================================

func BenchmarkInterfaceMethod_Retriable(b *testing.B) {
	err := &StreamError{Err: errors.New("stream exhausted"), isRetriable: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var retriableErr RetriableError
		if errors.As(err, &retriableErr) {
			_ = retriableErr.IsRetriable()
		}
	}
}

func BenchmarkInterfaceMethod_ShouldRetry(b *testing.B) {
	err := &StreamError{Err: errors.New("stream exhausted"), isRetriable: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShouldRetryStreamOperationFast(err)
	}
}

// ============================================================================
// Benchmark: Multiple Checks (Real-world Scenario)
// ============================================================================

// Simulates checking multiple error properties
func BenchmarkMultipleChecks_StringMatching(b *testing.B) {
	err := errors.New("lookup example.com: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errStr := err.Error()
		isTimeout := contains(errStr, "timeout")
		isLookup := contains(errStr, "lookup")
		isTemporary := contains(errStr, "temporary")
		_ = isTimeout && isLookup && !isTemporary
	}
}

func BenchmarkMultipleChecks_BitFlags(b *testing.B) {
	err := &FlaggedError{
		Err:   errors.New("lookup example.com: i/o timeout"),
		Flags: FlagTimeout | FlagTemporary,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var flaggedErr *FlaggedError
		if errors.As(err, &flaggedErr) {
			isTimeout := flaggedErr.HasFlag(FlagTimeout)
			isTemporary := flaggedErr.HasFlag(FlagTemporary)
			isRetriable := flaggedErr.HasFlag(FlagRetriable)
			_ = isTimeout && isTemporary && !isRetriable
		}
	}
}

// ============================================================================
// Benchmark: Error Wrapping Chain
// ============================================================================

func BenchmarkWrappingChain_Shallow(b *testing.B) {
	// Single level wrapping
	baseErr := ErrDNSTimeout
	wrappedErr := fmt.Errorf("operation failed: %w", baseErr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutHybrid(wrappedErr)
	}
}

func BenchmarkWrappingChain_Deep(b *testing.B) {
	// Multiple levels of wrapping
	baseErr := ErrDNSTimeout
	wrappedErr1 := fmt.Errorf("level 1: %w", baseErr)
	wrappedErr2 := fmt.Errorf("level 2: %w", wrappedErr1)
	wrappedErr3 := fmt.Errorf("level 3: %w", wrappedErr2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeoutHybrid(wrappedErr3)
	}
}

// ============================================================================
// Benchmark: Comparison Table
// ============================================================================

// This benchmark provides a comprehensive comparison of all methods.
// Run with: go test -bench=. -benchmem -benchtime=2s

/*
Expected Results (approximate):

Method                              | Speed      | Memory | Use Case
------------------------------------|------------|--------|------------------
Direct Comparison (==)              | ~1 ns/op   | 0 B    | Sentinel errors
Bit Flags (HasFlag)                 | ~2 ns/op   | 0 B    | Multiple checks
Cached String                       | ~2-3 ns/op | 0 B    | Repeated checks
Type Assertion (*DNSError)          | ~3-5 ns/op | 0 B    | Custom types
Interface Method (IsRetriable)      | ~5-10 ns/op| 0 B    | Complex logic
errors.Is() (standard)              | ~10-20 ns/op| 0 B   | Wrapped errors
String Matching (strings.Contains)  | ~20-100 ns/op| 0 B  | Fallback

Key Insights:
1. Direct comparison is fastest but only works for sentinel errors
2. Bit flags are excellent for multiple error properties
3. Type assertion provides good balance of speed and flexibility
4. String matching is slowest but most flexible
5. Hybrid approach gives best of all worlds
*/
