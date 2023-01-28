/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package logger

import "github.com/sirupsen/logrus"

func NewLogger(verbose int) *logrus.Logger {
	log := logrus.New()

	var level logrus.Level
	switch verbose {
	case 0:
		level = logrus.WarnLevel
	case 1:
		level = logrus.InfoLevel
	default:
		level = logrus.TraceLevel
	}

	log.SetLevel(level)

	return log
}
