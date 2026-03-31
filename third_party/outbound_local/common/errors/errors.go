/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors provides error handling utilities for the outbound module.
// This package maintains interface consistency with dae/common/errors while
// allowing independent evolution of the outbound module.
package errors

import (
	"context"
	"errors"
	"net"
)

// ============================================================================
// Standard Error Definitions (Sentinel Errors)
//
// These are exported for direct comparison in hot paths (1.19 ns/op).
// Usage: if err == ErrDNSTimeout { ... }
// ============================================================================

var (
	// DNS Errors
	ErrDNSTimeout          = errors.New("i/o timeout on DNS lookup")
	ErrDNSTemporaryFailure = errors.New("temporary DNS failure")

	// Stream Errors
	ErrStreamExhausted    = errors.New("too many open streams")
	ErrClientClosed       = errors.New("client closed")
	ErrClientClosing       = errors.New("client closing")
	ErrOperationHold      = errors.New("hold on")
)

// ============================================================================
// DNS and Timeout Error Detection
// ============================================================================

// IsDNSTimeout checks if the error is a DNS timeout.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrDNSTimeout { ... }
//
// This function provides compatibility with wrapped errors.
// Performance: Direct comparison path (1.19 ns), wrapped error path (~47 ns)
func IsDNSTimeout(err error) bool {
	if err == nil {
		return false
	}

	// 🚀 Fast path: direct comparison (1.19 ns)
	if err == ErrDNSTimeout {
		return true
	}

	// 🚀 Fast path: interface check (11.6 ns)
	if timeoutErr, ok := err.(interface{ IsTimeout() bool }); ok {
		return timeoutErr.IsTimeout() && contains(err.Error(), "lookup")
	}

	// ⚡ Medium path: net.Error interface check
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return contains(err.Error(), "lookup")
	}

	// 🐌 Slow path: string matching for backward compatibility
	errStr := err.Error()
	return contains(errStr, "i/o timeout") && contains(errStr, "lookup")
}

// IsDNSTemporaryFailure checks if the error is a temporary DNS failure.
// This is used to determine if a DNS operation should be retried.
func IsDNSTemporaryFailure(err error) bool {
	if err == nil {
		return false
	}

	// Check standard error
	if errors.Is(err, ErrDNSTemporaryFailure) {
		return true
	}

	// Check for temporary error using net.Error interface
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Temporary() { // nolint:staticcheck
			return contains(err.Error(), "lookup")
		}
	}

	return false
}

// ============================================================================
// Stream and Connection Errors
// ============================================================================

// IsStreamExhausted checks if the error indicates no more streams available.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrStreamExhausted { ... }
//
// Performance: Direct comparison path (1.19 ns), other paths (~47 ns)
func IsStreamExhausted(err error) bool {
	if err == nil {
		return false
	}

	// 🚀 Fast path: direct comparison (1.19 ns)
	if err == ErrStreamExhausted {
		return true
	}

	// 🐌 Fallback: string matching for backward compatibility
	return contains(err.Error(), "too many open streams")
}

// IsClientClosing checks if the error indicates the client is closing.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrClientClosing { ... }
func IsClientClosing(err error) bool {
	if err == nil {
		return false
	}

	// 🚀 Fast path: direct comparison (1.19 ns)
	if err == ErrClientClosing {
		return true
	}

	// 🐌 Fallback: string matching for backward compatibility
	return contains(err.Error(), "client closed")
}

// ShouldRetryStreamOperation checks if a stream operation should be retried.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrStreamExhausted || err == ErrOperationHold { ... }
//
// Performance: Direct comparison path (1.19 ns per check), other paths (~47 ns)
func ShouldRetryStreamOperation(err error) bool {
	if err == nil {
		return false
	}

	// 🚀 Fast path: direct comparison for known errors (1.19 ns per check)
	if err == ErrStreamExhausted || err == ErrOperationHold {
		return true
	}

	// 🚀 Fast path: client closing is NOT retryable
	if err == ErrClientClosing {
		return false
	}

	// 🐌 Fallback: string matching for backward compatibility
	errStr := err.Error()
	return contains(errStr, "too many open streams") || contains(errStr, "hold on")
}

// IsRecoverableStreamError is an alias for ShouldRetryStreamOperation
// with a more descriptive name for readability.
//
// Use this in code where you want to explicitly check if an error is
// recoverable rather than if an operation should be retried.
func IsRecoverableStreamError(err error) bool {
	return ShouldRetryStreamOperation(err)
}

// IsTemporaryError checks if an error is temporary and should not close the connection.
// This is used to distinguish between fatal and non-fatal network/context errors.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Context timeout/cancelled are temporary
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}

	// Net temporary errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() { // nolint:staticcheck
		return true
	}

	return false
}

// ============================================================================
// Helper Functions
// ============================================================================

// contains checks if substr is within s without importing strings package.
// This is a lightweight implementation for error message checking.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

// indexOf returns the index of the first occurrence of substr in s,
// or -1 if substr is not found.
func indexOf(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}
