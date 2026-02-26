/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/olicesx/quic-go"
)

// ============================================================================
// Standard Error Definitions
// ============================================================================

// Base error types for error wrapping and checking.
// These errors follow Go 1.13+ error wrapping conventions.

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
// Connection Error Detection
// ============================================================================

// isIgnorableTCPRelayError checks if the error is an ignorable connection error
// that occurs during normal TCP relay operation.
// Uses error wrapping (errors.Is) for reliable type checking instead of string matching.
func isIgnorableTCPRelayError(err error) bool {
	if err == nil {
		return false
	}

	// Check standard library errors first
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	// Check for broken pipe (EPIPE)
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EPIPE) {
			return true
		}
		// Connection reset by peer (ECONNRESET)
		if errors.Is(sysErr.Err, syscall.ECONNRESET) {
			return true
		}
	}

	// Check for QUIC stream errors (normal connection closure)
	// The quic.StreamError implements Is() for proper error matching
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		// Stream canceled by local or remote is normal closure
		// Error code 0 indicates normal closure (no error)
		return true
	}

	// Check for network timeout errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Fallback: check if error message contains known patterns
	// This maintains backward compatibility with custom error types
	// that may not properly implement error unwrapping
	errStr := err.Error()
	return containsIgnorableErrorPattern(errStr)
}

// isClosedConnectionError checks if the error indicates a closed connection/listener.
// This is used to suppress expected errors during shutdown.
func isClosedConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Standard check using errors.Is
	if errors.Is(err, ErrClosedListener) || errors.Is(err, ErrClosedConnection) {
		return true
	}

	// Check by error message for backward compatibility
	return contains(err.Error(), "use of closed network connection")
}

// isNetworkUnreachableError checks if the error is due to network unreachability.
func isNetworkUnreachableError(err error) bool {
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
	return hasSuffix(err.Error(), "network is unreachable")
}

// isAddressNotSuitableError checks if the error is due to address unsuitability.
func isAddressNotSuitableError(err error) bool {
	if err == nil {
		return false
	}

	// Check standard error
	if errors.Is(err, ErrAddressNotSuitable) {
		return true
	}

	// Check by error message for backward compatibility
	errStr := err.Error()
	return hasSuffix(errStr, "no suitable address found") ||
		hasSuffix(errStr, "non-IPv4 address")
}

// containsIgnorableErrorPattern provides fallback pattern matching
// for errors that don't properly implement error wrapping.
// This should rarely be needed if all error types follow Go best practices.
func containsIgnorableErrorPattern(s string) bool {
	// Check for specific error patterns that indicate normal connection closure
	patterns := []string{
		"write: broken pipe",
		"i/o timeout",
		"connection reset by peer",
		"canceled by local with error code 0",
		"canceled by remote with error code 0",
		"use of closed network connection",
	}

	for _, p := range patterns {
		if contains(s, p) {
			return true
		}
	}
	return false
}

// ============================================================================
// BPF Error Detection
// ============================================================================

// isBTFNotFoundError checks if the error indicates BTF is not available.
func isBTFNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrNoBTFFound) {
		return true
	}

	return contains(err.Error(), "no BTF found for kernel version")
}

// isUnknownBPFFuncError checks if the error indicates an unknown BPF function.
// Returns the function name if found, empty string otherwise.
func isUnknownBPFFuncError(err error) (funcName string, ok bool) {
	if err == nil {
		return "", false
	}

	if errors.Is(err, ErrUnknownBPFFunc) {
		return "", true
	}

	errStr := err.Error()
	if contains(errStr, "unknown func bpf_trace_printk") {
		return "bpf_trace_printk", true
	}
	if contains(errStr, "unknown func bpf_probe_read") {
		return "bpf_probe_read", true
	}
	return "", false
}

// wrapBPFError wraps BPF-related errors with helpful messages.
// Returns the original error with additional context, or the original error if not BPF-related.
func wrapBPFError(err error) error {
	if err == nil {
		return nil
	}

	if isBTFNotFoundError(err) {
		return fmt.Errorf("%w: you should re-compile linux kernel with BTF configurations; see docs for more information", err)
	}

	if funcName, ok := isUnknownBPFFuncError(err); ok {
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
// String Utilities (avoiding strings package import overhead)
// ============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func hasPrefix(s, prefix string) bool {
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
