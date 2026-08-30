/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

// cstLocation is the CST (UTC+8) location used for log timestamps.
// Initialized once at package init with a graceful fallback for systems
// without tzdata (e.g., minimal OpenWrt/ImmortalWrt builds).
var cstLocation *time.Location

func init() {
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		cstLocation = loc
	} else {
		cstLocation = time.FixedZone("CST", 8*3600)
	}
}

// isJournaldStream returns true if dae's stdout/stderr is captured by systemd's
// journald.  Systemd sets the JOURNAL_STREAM environment variable for each
// service's standard streams (value is "device:inode").  When true we suppress
// dae's own timestamp to avoid the redundant "journald prefix + CST timestamp"
// double-prefix that PR #1021 introduced by removing --disable-timestamp from
// dae.service.
func isJournaldStream() bool {
	return os.Getenv("JOURNAL_STREAM") != ""
}

// cstFormatter wraps prefixed.TextFormatter to use CST timezone for timestamps
// without modifying the global time.Local, which would affect unrelated code.
type cstFormatter struct {
	*prefixed.TextFormatter
}

// Format overrides the timestamp formatting to use CST timezone.
func (f *cstFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Create a copy of the entry to avoid modifying the shared entry object
	if !f.DisableTimestamp && entry.Time != (time.Time{}) {
		modifiedEntry := *entry
		modifiedEntry.Time = entry.Time.In(cstLocation)
		return f.TextFormatter.Format(&modifiedEntry)
	}
	return f.TextFormatter.Format(entry)
}

func SetLogger(log *logrus.Logger, logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
	// Auto-disable timestamp under journald to avoid double prefix.
	// When writing to a logfile we always emit the CST timestamp (the file
	// needs a self-describing timestamp).  --disable-timestamp still forces
	// suppression for callers that explicitly want it.
	if !disableTimestamp && isJournaldStream() && logFileOpt == nil {
		disableTimestamp = true
	}
	log.SetFormatter(&cstFormatter{
		TextFormatter: &prefixed.TextFormatter{
			DisableTimestamp: disableTimestamp,
			FullTimestamp:    true,
			ForceFormatting:  true,
			TimestampFormat:  "2006-01-02 15:04:05",
		},
	})
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}
}
