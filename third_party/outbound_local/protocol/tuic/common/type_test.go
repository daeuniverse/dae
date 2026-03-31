package common

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// mockNetError implements net.Error for testing
type mockNetError struct {
	msg       string
	timeout   bool
	temporary bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

func TestIsTemporaryError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name: "net temporary error",
			err: &mockNetError{
				msg:       "temporary network error",
				timeout:   false,
				temporary: true,
			},
			expected: true,
		},
		{
			name: "net timeout error (temporary)",
			err: &mockNetError{
				msg:       "timeout error",
				timeout:   true,
				temporary: true,
			},
			expected: true,
		},
		{
			name: "net permanent error",
			err: &mockNetError{
				msg:       "permanent error",
				timeout:   false,
				temporary: false,
			},
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "client closed error",
			err:      ErrClientClosed,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTemporaryError(tt.err)
			if result != tt.expected {
				t.Errorf("IsTemporaryError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsTemporaryErrorWithWrappedErrors(t *testing.T) {
	// Test wrapped context errors
	wrappedDeadline := fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
	if !IsTemporaryError(wrappedDeadline) {
		t.Error("IsTemporaryError should return true for wrapped context.DeadlineExceeded")
	}

	wrappedCanceled := fmt.Errorf("wrapped: %w", context.Canceled)
	if !IsTemporaryError(wrappedCanceled) {
		t.Error("IsTemporaryError should return true for wrapped context.Canceled")
	}
}
