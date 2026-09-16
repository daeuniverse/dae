/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"testing"
)

func TestAttachPreparedSessionManagerPreservesPriorError(t *testing.T) {
	prior := errors.New("build failed")
	if err := attachPreparedSessionManager(nil, nil, prior); err != prior {
		t.Fatalf("attachPreparedSessionManager() = %v, want prior construction error", err)
	}
}

func TestAttachPreparedSessionManagerSkipsNilCandidate(t *testing.T) {
	if err := attachPreparedSessionManager(nil, nil, nil); err != nil {
		t.Fatalf("attachPreparedSessionManager(nil) = %v, want nil", err)
	}
}
