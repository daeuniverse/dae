/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

func NewLogger(logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) *logrus.Logger {
	log := logrus.New()

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&prefixed.TextFormatter{
		DisableTimestamp: disableTimestamp,
		FullTimestamp:    true,
		TimestampFormat:  "Jan 02 15:04:05",
	})
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}

	return log
}
