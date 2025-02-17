/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import "github.com/sirupsen/logrus"

var (
	logger = logrus.StandardLogger()
)

func SetLogger(l *logrus.Logger) {
	logger = l
}
