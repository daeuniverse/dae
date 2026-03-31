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
// Unit Tests
// ============================================================================

func TestIsDNSTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "DNS timeout with lookup",
			err:  fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout"),
			want: true,
		},
		{
			name: "standard DNS timeout error",
			err:  ErrDNSTimeout,
			want: true,
		},
		{
			name: "wrapped DNS timeout",
			err:  fmt.Errorf("operation failed: %w", ErrDNSTimeout),
			want: true,
		},
		{
			name: "net.Error with timeout and lookup",
			err:  &testNetError{timeout: true, msg: "lookup example.com: i/o timeout"},
			want: true,
		},
		{
			name: "non-DNS timeout",
			err:  fmt.Errorf("i/o timeout"),
			want: false,
		},
		{
			name: "lookup without timeout",
			err:  fmt.Errorf("lookup example.com: no such host"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDNSTimeout(tt.err); got != tt.want {
				t.Errorf("IsDNSTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDNSTemporaryFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "temporary DNS failure",
			err:  ErrDNSTemporaryFailure,
			want: true,
		},
		{
			name: "wrapped temporary DNS failure",
			err:  fmt.Errorf("operation failed: %w", ErrDNSTemporaryFailure),
			want: true,
		},
		{
			name: "net.Error with temporary and lookup",
			err:  &testNetError{temporary: true, msg: "lookup example.com: temporary failure"},
			want: true,
		},
		{
			name: "temporary error without lookup",
			err:  &testNetError{temporary: true, msg: "connection timeout"},
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDNSTemporaryFailure(tt.err); got != tt.want {
				t.Errorf("IsDNSTemporaryFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStreamExhausted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "too many open streams error",
			err:  errors.New("too many open streams"),
			want: true,
		},
		{
			name: "wrapped stream exhausted error",
			err:  fmt.Errorf("operation failed: too many open streams"),
			want: true,
		},
		{
			name: "other stream error",
			err:  errors.New("stream reset"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStreamExhausted(tt.err); got != tt.want {
				t.Errorf("IsStreamExhausted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsClientClosing(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "client closed error",
			err:  errors.New("client closed"),
			want: true,
		},
		{
			name: "wrapped client closing error",
			err:  fmt.Errorf("operation failed: client closed"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("connection timeout"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClientClosing(tt.err); got != tt.want {
				t.Errorf("IsClientClosing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldRetryStreamOperation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "stream exhausted - should retry",
			err:  errors.New("too many open streams"),
			want: true,
		},
		{
			name: "hold on error - should retry",
			err:  errors.New("hold on"),
			want: true,
		},
		{
			name: "client closing - should not retry",
			err:  errors.New("client closed"),
			want: false,
		},
		{
			name: "other error - should not retry",
			err:  errors.New("connection reset"),
			want: false,
		},
		{
			name: "nil error - should not retry",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldRetryStreamOperation(tt.err); got != tt.want {
				t.Errorf("ShouldRetryStreamOperation() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

// Benchmark old string-matching approach vs new type-safe approach

func BenchmarkIsDNSTimeout_StringMatch(b *testing.B) {
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach: string matching
		errStr := err.Error()
		_ = contains(errStr, "i/o timeout") && contains(errStr, "lookup")
	}
}

func BenchmarkIsDNSTimeout_TypeSafe(b *testing.B) {
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach: type-safe check
		_ = IsDNSTimeout(err)
	}
}

func BenchmarkIsDNSTimeout_TypeSafeWrapped(b *testing.B) {
	err := fmt.Errorf("operation failed: %w", ErrDNSTimeout)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeout(err)
	}
}

func BenchmarkIsStreamExhausted_StringMatch(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach: string matching
		_ = contains(err.Error(), "too many open streams")
	}
}

func BenchmarkIsStreamExhausted_TypeSafe(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach: type-safe check
		_ = IsStreamExhausted(err)
	}
}

func BenchmarkShouldRetryStreamOperation_Complex(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach: complex string matching
		errStr := err.Error()
		_ = contains(errStr, "too many open streams") ||
			contains(errStr, "client closed") ||
			contains(errStr, "hold on")
	}
}

func BenchmarkShouldRetryStreamOperation_TypeSafe(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach: type-safe check
		_ = ShouldRetryStreamOperation(err)
	}
}

// ============================================================================
// Helper Types
// ============================================================================

// testNetError implements net.Error for testing
type testNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *testNetError) Error() string   { return e.msg }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return e.temporary }
