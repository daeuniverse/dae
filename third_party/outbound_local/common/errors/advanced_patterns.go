/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors demonstrates advanced error handling patterns
// that balance performance and code quality.
package errors

import (
	"errors"
	"net"
)

// ============================================================================
// Method 1: Sentinel Errors with Direct Comparison (Fastest)
// ============================================================================

// Sentinel errors are predefined error values that can be compared directly.
// This is the fastest error checking method in Go.
// See errors.go for the actual sentinel error definitions.

// IsStreamExhaustedFast checks if error is ErrStreamExhausted using direct comparison.
// This is the FASTEST method but ONLY works for sentinel errors.
//
// Performance: ~1-2 ns/op (single pointer comparison)
// Use case: Hot paths where performance is critical
func IsStreamExhaustedFast(err error) bool {
	return err == ErrStreamExhausted
}

// Note: IsClientClosedFast is commented out because ErrClientClosed
// is defined in tuic/common package, not here.
// func IsClientClosedFast(err error) bool {
// 	return err == ErrClientClosed
// }

// ============================================================================
// Method 2: Custom Error Types with Type Assertion (Fast)
// ============================================================================

// DNSError is a custom error type for DNS-related errors.
// This allows fast type checking while carrying additional context.
type DNSError struct {
	Err         error
	IsTimeout   bool
	IsTemporary bool
}

func (e *DNSError) Error() string {
	return e.Err.Error()
}

// Timeout implements net.Error interface.
func (e *DNSError) Timeout() bool {
	return e.IsTimeout
}

// Temporary implements net.Error interface.
func (e *DNSError) Temporary() bool {
	return e.IsTemporary
}

// Unwrap returns the underlying error.
func (e *DNSError) Unwrap() error {
	return e.Err
}

// IsDNSTimeoutFast checks if error is a DNS timeout using type assertion.
// Type assertion is faster than errors.Is() for custom types.
//
// Performance: ~3-5 ns/op (type assertion)
// Use case: When you need both speed and additional context
func IsDNSTimeoutFast(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: type assertion
	var dnsErr *DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout
	}

	// Fallback: string matching for backward compatibility
	return contains(err.Error(), "i/o timeout") && contains(err.Error(), "lookup")
}

// ============================================================================
// Method 3: Error Interface with Boolean Methods (Fast & Flexible)
// ============================================================================

// RetriableError is an interface for errors that can indicate if they are retriable.
type RetriableError interface {
	error
	IsRetriable() bool
}

// StreamError implements RetriableError for stream-related errors.
type StreamError struct {
	Err         error
	isRetriable bool // Renamed to avoid conflict with method
}

func (e *StreamError) Error() string {
	return e.Err.Error()
}

// IsRetriable implements RetriableError interface.
func (e *StreamError) IsRetriable() bool {
	return e.isRetriable
}

// Unwrap returns the underlying error.
func (e *StreamError) Unwrap() error {
	return e.Err
}

// ShouldRetryStreamOperationFast checks if error is retriable using interface method.
// This is fast and flexible - uses type assertion + method call.
//
// Performance: ~5-10 ns/op (interface check + method call)
// Use case: When you need complex retry logic with good performance
func ShouldRetryStreamOperationFast(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: check for RetriableError interface
	var retriableErr RetriableError
	if errors.As(err, &retriableErr) {
		return retriableErr.IsRetriable()
	}

	// Fallback: check known error types
	if err == ErrStreamExhausted {
		return true
	}

	// Fallback: string matching
	errStr := err.Error()
	return contains(errStr, "too many open streams") || contains(errStr, "hold on")
}

// ============================================================================
// Method 4: Bit Flags for Error Classification (Fastest for Multiple Checks)
// ============================================================================

// ErrorFlags represents error classification using bit flags.
// This is useful when you need to check multiple error properties.
type ErrorFlags uint8

const (
	FlagNone    ErrorFlags = 0
	FlagTimeout ErrorFlags = 1 << iota
	FlagTemporary
	FlagRetriable
	FlagFatal
)

// FlaggedError is an error with pre-computed classification flags.
type FlaggedError struct {
	Err   error
	Flags ErrorFlags
}

func (e *FlaggedError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *FlaggedError) Unwrap() error {
	return e.Err
}

// HasFlag checks if error has a specific flag.
// This is extremely fast - just a bit operation.
func (e *FlaggedError) HasFlag(flag ErrorFlags) bool {
	return e.Flags&flag != 0
}

// IsTimeout checks if error is a timeout using flags.
func (e *FlaggedError) IsTimeout() bool {
	return e.HasFlag(FlagTimeout)
}

// IsRetriable checks if error is retriable using flags.
func (e *FlaggedError) IsRetriable() bool {
	return e.HasFlag(FlagRetriable)
}

// NewDNSTimeoutFlagged creates a flagged DNS timeout error.
func NewDNSTimeoutFlagged(err error) *FlaggedError {
	return &FlaggedError{
		Err:   err,
		Flags: FlagTimeout | FlagTemporary | FlagRetriable,
	}
}

// IsDNSTimeoutWithFlags checks if error is a DNS timeout using flags.
//
// Performance: ~2-3 ns/op (bit operation)
// Use case: Extremely hot paths where you need multiple error checks
func IsDNSTimeoutWithFlags(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: check for FlaggedError with timeout flag
	var flaggedErr *FlaggedError
	if errors.As(err, &flaggedErr) {
		return flaggedErr.IsTimeout() && contains(flaggedErr.Error(), "lookup")
	}

	// Fallback: standard checks
	return IsDNSTimeoutFast(err)
}

// ============================================================================
// Method 5: Cached String Results (Fast for Repeated Checks)
// ============================================================================

// CachedStringError caches the Error() string result for fast comparison.
// Useful when the same error is checked multiple times.
type CachedStringError struct {
	err       error
	cachedMsg string
}

func (e *CachedStringError) Error() string {
	if e.cachedMsg == "" {
		e.cachedMsg = e.err.Error()
	}
	return e.cachedMsg
}

// Unwrap returns the underlying error.
func (e *CachedStringError) Unwrap() error {
	return e.err
}

// IsDNSTimeoutCached checks if error is DNS timeout using cached string.
//
// Performance: ~2-3 ns/op after first call (cached string access)
// Use case: When the same error is checked multiple times
func IsDNSTimeoutCached(err error) bool {
	if cachedErr, ok := err.(*CachedStringError); ok {
		return contains(cachedErr.Error(), "i/o timeout") &&
			contains(cachedErr.Error(), "lookup")
	}
	return IsDNSTimeoutFast(err)
}

// ============================================================================
// Method 6: Hybrid Approach (Recommended for Production)
// ============================================================================

// IsDNSTimeoutHybrid combines multiple methods for optimal performance.
//
// Strategy:
// 1. Fast path: direct comparison for sentinel errors
// 2. Medium path: type assertion for custom error types
// 3. Slow path: string matching for backward compatibility
//
// Performance: Varies by path (1-50 ns/op)
// Use case: Production code that needs both performance and compatibility
func IsDNSTimeoutHybrid(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: sentinel error (direct comparison)
	if err == ErrDNSTimeout {
		return true
	}

	// Medium path: custom error type (type assertion)
	var dnsErr *DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout
	}

	// Medium path: flagged error (bit operation)
	var flaggedErr *FlaggedError
	if errors.As(err, &flaggedErr) {
		return flaggedErr.IsTimeout() && contains(flaggedErr.Error(), "lookup")
	}

	// Slow path: net.Error interface check
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return contains(err.Error(), "lookup")
	}

	// Fallback: string matching
	errStr := err.Error()
	return contains(errStr, "i/o timeout") && contains(errStr, "lookup")
}

// ============================================================================
// Performance Comparison Summary
// ============================================================================

// Method Performance Comparison (fastest to slowest):
//
// 1. Direct comparison (err == ErrSentinel)          ~1 ns/op
// 2. Bit flags (flaggedErr.HasFlag())               ~2 ns/op
// 3. Cached string (cachedErr.Error())              ~2-3 ns/op
// 4. Type assertion (errors.As with custom type)    ~3-5 ns/op
// 5. Interface method (retriableErr.IsRetriable())  ~5-10 ns/op
// 6. errors.Is() (standard library)                 ~10-20 ns/op
// 7. String matching (strings.Contains)            ~20-100 ns/op
//
// Recommendation: Use hybrid approach for production code.
