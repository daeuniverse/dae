/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

type mockCgroupAttachment struct {
	closeErr error
}

func (m *mockCgroupAttachment) Close() error {
	return m.closeErr
}

func TestCgroupDetachErrorContext(t *testing.T) {
	origDetect := detectCgroupPathFunc
	origAttach := attachCgroupFunc
	t.Cleanup(func() {
		detectCgroupPathFunc = origDetect
		attachCgroupFunc = origAttach
	})

	detectCgroupPathFunc = func() (string, error) {
		return "/sys/fs/cgroup", nil
	}

	mockErr := errors.New("simulated detach failure")
	attachCgroupFunc = func(opts ciliumLink.CgroupOptions) (cgroupAttachment, error) {
		return &mockCgroupAttachment{closeErr: mockErr}, nil
	}

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	core := &controlPlaneCore{
		log:                logger,
		closed:             context.Background(),
		bpfHookDetachFuncs: make([]func() error, 0),
		tcHooks:            newTCHookSet(logger),
	}
	core.bpf.Store(&bpfObjects{})

	if err := core.setupSkPidMonitor(); err != nil {
		t.Fatalf("setupSkPidMonitor: %v", err)
	}

	detachErr := core.DetachBpfHooks()
	if detachErr == nil {
		t.Fatal("expected detach error, got nil")
	}

	errStr := detachErr.Error()
	if strings.Contains(errStr, "inet6Bind.Close()") {
		t.Errorf("detach error still contains outdated inet6Bind.Close() context: %v", errStr)
	}

	for _, expectedName := range []string{
		"cgroup sock_create detach",
		"cgroup sock_release detach",
		"cgroup connect4 detach",
		"cgroup connect6 detach",
		"cgroup sendmsg4 detach",
		"cgroup sendmsg6 detach",
	} {
		if !strings.Contains(errStr, expectedName) {
			t.Errorf("detach error missing context %q: %v", expectedName, errStr)
		}
	}
}
