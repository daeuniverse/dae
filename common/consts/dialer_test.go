/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"testing"
)

func TestL4ProtoStr_ToL4ProtoType(t *testing.T) {
	// Just verify it doesn't panic for known types
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("The code panicked: %v", r)
		}
	}()

	if got := L4ProtoStr_TCP.ToL4ProtoType(); got != L4ProtoType_TCP {
		t.Errorf("Expected TCP, got %v", got)
	}
	if got := L4ProtoStr_UDP.ToL4ProtoType(); got != L4ProtoType_UDP {
		t.Errorf("Expected UDP, got %v", got)
	}
}
