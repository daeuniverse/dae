/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestDialerSetParseErrorDoesNotLogNodeLink(t *testing.T) {
	const secret = "uuid-password-token"
	var logs bytes.Buffer
	log := logrus.New()
	log.SetOutput(&logs)
	set := NewDialerSetFromLinks(&dialer.GlobalOption{Log: log}, map[string][]string{
		"remote": {"unknown://" + secret},
	})
	defer func() { _ = set.Close() }()
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("log leaked node credentials: %s", logs.String())
	}
}
