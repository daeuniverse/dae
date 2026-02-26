/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors provides standardized error checking and utilities
// across the dae project following Go 1.20+ error handling best practices.
package errors

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

// ============================================================================
// Standard Error Definitions
// ============================================================================

// Base error types for error wrapping and checking.
// These errors follow Go 1.13+ error wrapping conventions and can be
// checked using errors.Is() and errors.As().

var (
	// ErrClosedListener indicates the listener was closed.
	// This is an expected error during shutdown and should be suppressed.
	ErrClosedListener = errors.New("listener closed")

	// ErrNetworkUnreachable indicates network is not reachable.
	ErrNetworkUnreachable = errors.New("network is unreachable")

	// ErrAddressNotSuitable indicates no suitable address found.
	ErrAddressNotSuitable = errors.New("no suitable address found")

	// ErrClosedConnection indicates use of a closed network connection.
	ErrClosedConnection = errors.New("use of closed network connection")

	// ErrDialerUnavailable indicates the dialer is not available.
	ErrDialerUnavailable = errors.New("dialer unavailable")

	// ErrNoBTFFound indicates BTF is not enabled in kernel.
	ErrNoBTFFound = errors.New("no BTF found for kernel version")

	// ErrUnknownBPFFunc indicates unknown BPF function.
	ErrUnknownBPFFunc = errors.New("unknown BPF function")
)

// ============================================================================
// Network Error Detection
// ============================================================================

// IsClosedConnection checks if the error indicates a closed connection/listener.
// This is used to suppress expected errors during shutdown.
//
// Examples:
//   - "use of closed network connection"
//   - Listener closed during shutdown
func IsClosedConnection(err error) bool {
	if err == nil {
		return false
	}

	// Standard check using errors.Is
	if errors.Is(err, ErrClosedListener) || errors.Is(err, ErrClosedConnection) {
		return true
	}

	// Check by error message for backward compatibility
	return Contains(err.Error(), "use of closed network connection")
}

// IsNetworkUnreachable checks if the error is due to network unreachability.
//
// Examples:
//   - syscall.ENETUNREACH
//   - "network is unreachable"
func IsNetworkUnreachable(err error) bool {
	if err == nil {
		return false
	}

	// Check standard error
	if errors.Is(err, ErrNetworkUnreachable) {
		return true
	}

	// Check syscall errors
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.ENETUNREACH) {
			return true
		}
	}

	// Check by error message for backward compatibility
	return HasSuffix(err.Error(), "network is unreachable")
}

// IsAddressNotSuitable checks if the error is due to address unsuitability.
//
// Examples:
//   - "no suitable address found"
//   - "non-IPv4 address"
func IsAddressNotSuitable(err error) bool {
	if err == nil {
		return false
	}

	// Check standard error
	if errors.Is(err, ErrAddressNotSuitable) {
		return true
	}

	// Check by error message for backward compatibility
	errStr := err.Error()
	return HasSuffix(errStr, "no suitable address found") ||
		HasSuffix(errStr, "non-IPv4 address")
}

// IsIgnorableConnectionError checks if the error is an ignorable connection error
// that occurs during normal network operation. This includes:
//   - EOF (normal connection closure)
//   - Timeout errors
//   - Broken pipe (EPIPE)
//   - Connection reset by peer (ECONNRESET)
//   - Network timeout
func IsIgnorableConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for EOF
	if errors.Is(err, io.EOF) {
		return true
	}

	// Check for timeout
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Check for syscall errors
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EPIPE) ||
			errors.Is(sysErr.Err, syscall.ECONNRESET) ||
			errors.Is(sysErr.Err, syscall.ETIMEDOUT) {
			return true
		}
	}

	// Check by error message for backward compatibility
	errStr := err.Error()
	return Contains(errStr, "write: broken pipe") ||
		Contains(errStr, "i/o timeout") ||
		Contains(errStr, "connection reset by peer") ||
		Contains(errStr, "use of closed network connection")
}

// ============================================================================
// BPF Error Detection
// ============================================================================

// IsBTFNotFoundError checks if the error indicates BTF is not available.
func IsBTFNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrNoBTFFound) {
		return true
	}

	return Contains(err.Error(), "no BTF found for kernel version")
}

// IsUnknownBPFFuncError checks if the error indicates an unknown BPF function.
// Returns the function name if found, empty string otherwise.
func IsUnknownBPFFuncError(err error) (funcName string, ok bool) {
	if err == nil {
		return "", false
	}

	if errors.Is(err, ErrUnknownBPFFunc) {
		return "", true
	}

	errStr := err.Error()
	if Contains(errStr, "unknown func bpf_trace_printk") {
		return "bpf_trace_printk", true
	}
	if Contains(errStr, "unknown func bpf_probe_read") {
		return "bpf_probe_read", true
	}
	return "", false
}

// WrapBPFError wraps BPF-related errors with helpful messages.
// Returns the original error with additional context, or the original error if not BPF-related.
func WrapBPFError(err error) error {
	if err == nil {
		return nil
	}

	if IsBTFNotFoundError(err) {
		return fmt.Errorf("%w: you should re-compile linux kernel with BTF configurations; see docs for more information", err)
	}

	if funcName, ok := IsUnknownBPFFuncError(err); ok {
		switch funcName {
		case "bpf_trace_printk":
			return fmt.Errorf(`%w: please try to compile dae without bpf_printk`, err)
		case "bpf_probe_read":
			return fmt.Errorf(`%w: please re-compile linux kernel with CONFIG_BPF_EVENTS=y and CONFIG_KPROBE_EVENTS=y`, err)
		default:
			return fmt.Errorf("%w: unknown BPF function '%s'", err, funcName)
		}
	}

	return err
}

// ============================================================================
// DNS and Timeout Errors
// ============================================================================

var (
	// ErrDNSTimeout indicates DNS lookup timeout.
	ErrDNSTimeout = errors.New("i/o timeout on DNS lookup")

	// ErrDNSTemporaryFailure indicates temporary DNS failure.
	ErrDNSTemporaryFailure = errors.New("temporary DNS failure")
)

// IsDNSTimeout checks if the error is a DNS timeout.
// This matches errors that contain both "i/o timeout" and "lookup" in the message,
// which indicates a DNS lookup timeout.
//
// Best Practice (Go 1.20+):
//   - Use errors.As() to check for net.Error with Timeout()
//   - Use Contains() to verify "lookup" in message
//   - Avoid pure string matching when possible
//
// Example:
//   if IsDNSTimeout(err) {
//       // Handle DNS timeout
//   }
func IsDNSTimeout(err error) bool {
	if err == nil {
		return false
	}

	// Check standard error
	if errors.Is(err, ErrDNSTimeout) {
		return true
	}

	// Check for timeout using net.Error interface (Go 1.13+)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Verify it's DNS-related by checking for "lookup" in message
		return Contains(err.Error(), "lookup")
	}

	// Fallback: string matching for backward compatibility
	// This handles cases where timeout is wrapped or error type is not net.Error
	errStr := err.Error()
	return Contains(errStr, "i/o timeout") && Contains(errStr, "lookup")
}

// ============================================================================
// String Utilities
// ============================================================================

// These utilities avoid importing the strings package to reduce binary size
// and improve performance for hot paths.

// Contains reports whether substr is within s.
func Contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

// HasSuffix reports whether s ends with suffix.
func HasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// HasPrefix reports whether s starts with prefix.
func HasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

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
