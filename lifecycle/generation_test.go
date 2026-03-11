/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package lifecycle

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewGeneration(t *testing.T) {
	id := "test-gen-123"
	hash := "abc123"

	gen := NewGeneration(id, nil, hash)

	if gen.ID != id {
		t.Errorf("ID = %v, want %v", gen.ID, id)
	}
	if gen.ConfigHash != hash {
		t.Errorf("ConfigHash = %v, want %v", gen.ConfigHash, hash)
	}
	if gen.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be set")
	}
	if !gen.ActivatedAt.IsZero() {
		t.Errorf("ActivatedAt should be zero initially")
	}
}

func TestGeneration_IsActive(t *testing.T) {
	gen := NewGeneration("test", nil, "")

	if gen.IsActive() {
		t.Errorf("IsActive() = true, want false (not activated yet)")
	}

	gen.MarkActivated(time.Now())

	if !gen.IsActive() {
		t.Errorf("IsActive() = false, want true (after activation)")
	}
}

func TestGeneration_MarkActivated(t *testing.T) {
	gen := NewGeneration("test", nil, "")
	if !gen.ActivatedAt.IsZero() {
		t.Fatalf("ActivatedAt should be zero initially")
	}

	t1 := time.Now()
	gen.MarkActivated(t1)
	t2 := time.Now()

	if gen.ActivatedAt.Before(t1) || gen.ActivatedAt.After(t2) {
		t.Errorf("ActivatedAt = %v, want between %v and %v", gen.ActivatedAt, t1, t2)
	}
}

func TestGeneration_ConcurrentActivation(t *testing.T) {
	gen := NewGeneration("test", nil, "")

	// Test concurrent access
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = gen.IsActive()
		}()
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			gen.MarkActivated(time.Now())
		}(i)
	}

	wg.Wait()

	if !gen.IsActive() {
		t.Errorf("IsActive() = false after concurrent activation, want true")
	}
}

func TestGeneration_Close(t *testing.T) {
	tests := []struct {
		name       string
		setupOwned func() *OwnedResources
		wantErr    bool
	}{
		{
			name: "nil owned resources",
			setupOwned: func() *OwnedResources {
				return nil
			},
			wantErr: false,
		},
		{
			name: "empty owned resources",
			setupOwned: func() *OwnedResources {
				return &OwnedResources{}
			},
			wantErr: false,
		},
		{
			name: "with closable listener",
			setupOwned: func() *OwnedResources {
				return &OwnedResources{
					TProxyListener: &mockCloser{},
				}
			},
			wantErr: false,
		},
		{
			name: "with closable control plane",
			setupOwned: func() *OwnedResources {
				return &OwnedResources{
					ControlPlane: &mockCloser{},
				}
			},
			wantErr: false,
		},
		{
			name: "with failing closer",
			setupOwned: func() *OwnedResources {
				return &OwnedResources{
					ControlPlane: &mockCloser{err: &mockError{msg: "close failed"}},
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &Generation{
				ID:    "test-gen",
				Owned: tt.setupOwned(),
			}

			err := gen.Close()
			if (err != nil) != tt.wantErr {
				t.Errorf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMultiError(t *testing.T) {
	tests := []struct {
		name string
		errs []error
		want string
	}{
		{
			name: "nil errors",
			errs: nil,
			want: "",
		},
		{
			name: "empty errors",
			errs: []error{},
			want: "",
		},
		{
			name: "single error",
			errs: []error{&mockError{msg: "error 1"}},
			want: "error 1",
		},
		{
			name: "multiple errors",
			errs: []error{
				&mockError{msg: "error 1"},
				&mockError{msg: "error 2"},
			},
			want: "multiple errors:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := joinErrors(tt.errs)
			if err == nil {
				if tt.want != "" {
					t.Errorf("joinErrors() = nil, want %v", tt.want)
				}
			} else {
				if !strings.Contains(err.Error(), tt.want) {
					t.Errorf("joinErrors() = %v, want to contain %v", err.Error(), tt.want)
				}
			}
		})
	}
}

// Mock types for testing

type mockCloser struct {
	closed bool
	err    error
}

func (m *mockCloser) Close() error {
	m.closed = true
	return m.err
}

type mockError struct {
	msg string
}

func (m *mockError) Error() string {
	return m.msg
}
