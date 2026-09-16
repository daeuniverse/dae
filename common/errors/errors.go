/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors provides standardized error checking and utilities
// across the dae project following Go 1.20+ error handling best practices.
package errors

import (
	"context"
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
	if errors.Is(err, ErrClosedListener) || errors.Is(err, ErrClosedConnection) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}

	// Check by error message for backward compatibility
	return Contains(err.Error(), "use of closed network connection")
}

// IsCanceledOrClosed reports whether err came from request cancellation or a
// connection/listener being closed during lifecycle teardown. These errors are
// expected during reload/shutdown and must not poison dialer health state.
func IsCanceledOrClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	if IsClosedConnection(err) {
		return true
	}
	errStr := err.Error()
	return Contains(errStr, "context canceled") || Contains(errStr, "operation was canceled")
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
//
// This function is on the hot path and optimized for minimal overhead.
func IsIgnorableConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if IsCanceledOrClosed(err) {
		return true
	}

	// Fast path: sentinel errors (pointer comparison only)
	if errors.Is(err, io.EOF) {
		return true
	}

	// Check for timeout (type assertion fast path first)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	var netErrWrap net.Error
	if errors.As(err, &netErrWrap) && netErrWrap.Timeout() {
		return true
	}

	// Check for syscall errors
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EPIPE) ||
			errors.Is(sysErr.Err, syscall.ECONNRESET) ||
			errors.Is(sysErr.Err, syscall.ETIMEDOUT) ||
			errors.Is(sysErr.Err, syscall.ECONNREFUSED) ||
			errors.Is(sysErr.Err, syscall.EADDRNOTAVAIL) {
			return true
		}
	}

	// Slow path: single string allocation for pattern matching
	return ContainsIgnorableErrorPattern(err.Error())
}

// IsIgnorableTCPRelayError checks if the error is an ignorable connection error
// that occurs during normal TCP relay operation.
// This function is on the hot path and optimized for minimal overhead.
func IsIgnorableTCPRelayError(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: sentinel errors (pointer comparison only)
	if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	// Fast path: check wrapped syscall errors
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if errors.Is(sysErr.Err, syscall.EPIPE) || errors.Is(sysErr.Err, syscall.ECONNRESET) {
			return true
		}
	}

	// Check for network timeout errors (type assertion fast path first)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	var netErrWrap net.Error
	if errors.As(err, &netErrWrap) && netErrWrap.Timeout() {
		return true
	}

	// QUIC stream cancellation with error code 0 is a normal close.
	// Match the typed error, not the Error() string: a format change in
	// quic-go must not silently reclassify this as a real failure.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) && streamErr.ErrorCode == 0 {
		return true
	}

	// Slow path: single string allocation for all pattern checks
	errStr := err.Error()

	if isNormalWebSocketCloseErrorString(errStr) {
		return true
	}

	// Check common patterns (single string allocation reused)
	return ContainsIgnorableErrorPattern(errStr)
}

// IsUDPEndpointNormalClose reports whether err is a normal UDP endpoint closure.
// This function is called on the hot path (every UDP endpoint closure) and is
// optimized to minimize allocations and reflection overhead.
func IsUDPEndpointNormalClose(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: check sentinel errors first (no allocations, pointer comparison only)
	if errors.Is(err, io.EOF) ||
		errors.Is(err, ErrClosedListener) ||
		errors.Is(err, ErrClosedConnection) {
		return true
	}

	// Check for timeout errors (common for UDP NAT expiration)
	// Use type assertion fast path before errors.As reflection
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	var netErrWrap net.Error
	if errors.As(err, &netErrWrap) && netErrWrap.Timeout() {
		return true
	}

	// QUIC stream cancellation with error code 0 is a normal close.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) && streamErr.ErrorCode == 0 {
		return true
	}

	// Slow path: single string allocation for all string-based checks.
	// This handles wrapped errors that don't match sentinel errors.
	errStr := err.Error()

	if isNormalWebSocketCloseErrorString(errStr) {
		return true
	}

	// Check for closed connection (string-based for backward compatibility)
	if Contains(errStr, "use of closed network connection") {
		return true
	}

	// Check for replay attack error
	if isReplayFamilyErrorString(errStr) {
		return true
	}

	return false
}

// replayFamilyErrorSubstrings are the message fragments that mark a packet-level
// anti-replay rejection. SIP022 §3.2.3 treats a message timestamp outside the
// 30-second clock window as replay, but the outbound library reports that case
// with its own sentinel ("timestamp expired") so an operator can tell clock skew
// from a genuine replay. Both rejections are per-packet: the packet is dropped
// and the transport stays healthy. A consumer reacting to one of them reacts to
// that property, so both fragments must keep classifying the same way; splitting
// the outbound sentinel must not silently turn a stale timestamp into a fatal
// transport error.
var replayFamilyErrorSubstrings = [...]string{"replay attack", "timestamp expired"}

// isReplayFamilyErrorString reports whether a message names a replay-family
// rejection. Matching is string-based, like the rest of this file's slow path,
// because the outbound sentinel sits behind a module pin this module cannot
// import ahead of.
func isReplayFamilyErrorString(errStr string) bool {
	for _, pattern := range replayFamilyErrorSubstrings {
		if Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// IsReplayAttackError reports whether err is a replay attack error. An expired
// message timestamp counts: the packet is rejected for the same reason class and
// with the same per-packet consequence.
func IsReplayAttackError(err error) bool {
	if err == nil {
		return false
	}
	return isReplayFamilyErrorString(err.Error())
}

// IsAuthError reports whether err is an authentication error (e.g. AEAD check failed).
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	return Contains(err.Error(), "cipher: message authentication failed")
}

// ignorableErrorPatterns is a pre-allocated slice of error patterns to avoid
// heap allocations on the hot path. This is used by ContainsIgnorableErrorPattern.
var ignorableErrorPatterns = []string{
	"write: broken pipe",
	"i/o timeout",
	"connection reset by peer",
	"canceled by local with error code 0",
	"canceled by remote with error code 0",
	"use of closed network connection",
	"websocket: close 1000 (normal)",
	"websocket: close 1001 (going away)",
	"websocket: close sent",
}

// ContainsIgnorableErrorPattern provides fallback pattern matching
// for errors that don't properly implement error wrapping.
// Uses a pre-allocated slice to avoid heap allocations on the hot path.
func ContainsIgnorableErrorPattern(s string) bool {
	for _, p := range ignorableErrorPatterns {
		if Contains(s, p) {
			return true
		}
	}
	return false
}

func isNormalWebSocketCloseErrorString(s string) bool {
	return Contains(s, "websocket: close 1000 (normal)") ||
		Contains(s, "websocket: close 1001 (going away)") ||
		Contains(s, "websocket: close sent")
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
