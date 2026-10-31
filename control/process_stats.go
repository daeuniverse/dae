/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// userHZ is the unit of the utime/stime fields of /proc/<pid>/stat. Unlike the
// kernel's internal HZ it is a fixed part of the userspace ABI: Linux returns
// 100 from sysconf(_SC_CLK_TCK) on every architecture.
const userHZ = 100

// processCPUStats measures dae's own CPU time between two samples.
//
// The contract defines process.cpu_percent as the CPU time used over the
// server's latest sampling interval, as a percentage of one CPU: 100 means one
// core fully busy and the value may exceed 100 on a multi-core host. That is a
// delta, not a lifetime average, so the first sample only establishes a
// baseline and the field stays null until a second one arrives.
type processCPUStats struct {
	procSelf string

	mu      sync.Mutex
	lastCPU time.Duration
	lastAt  time.Time
	percent *float64
}

func newProcessCPUStats() *processCPUStats {
	return &processCPUStats{procSelf: "/proc/self"}
}

// readProcessCPUTime returns one process's user plus system CPU time.
func readProcessCPUTime(path string) (time.Duration, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	// The comm field is parenthesised and may contain spaces and parentheses of
	// its own, so the field list begins after the last ')'. Unwrapping from the
	// front would misparse a process named e.g. "a) b".
	line := string(data)
	end := strings.LastIndexByte(line, ')')
	if end < 0 || end+1 >= len(line) {
		return 0, false
	}
	fields := strings.Fields(line[end+1:])
	// utime and stime are fields 14 and 15 of the stat line. The slice starts at
	// field 3 (state), so they sit at offsets 11 and 12 here.
	const utimeOffset, stimeOffset = 11, 12
	if len(fields) <= stimeOffset {
		return 0, false
	}
	utime, err := strconv.ParseInt(fields[utimeOffset], 10, 64)
	if err != nil || utime < 0 {
		return 0, false
	}
	stime, err := strconv.ParseInt(fields[stimeOffset], 10, 64)
	if err != nil || stime < 0 {
		return 0, false
	}
	return time.Duration(utime+stime) * time.Second / userHZ, true
}

// sample folds one reading into the reported percentage. A reading that cannot
// be parsed clears the value instead of keeping a stale one, so an unreadable
// /proc renders as "unknown" rather than as an old number.
func (s *processCPUStats) sample(now time.Time) {
	if s == nil {
		return
	}
	cpu, ok := readProcessCPUTime(filepath.Join(s.procSelf, "stat"))

	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.lastAt = time.Time{}
		s.percent = nil
		return
	}
	prevCPU, prevAt := s.lastCPU, s.lastAt
	s.lastCPU, s.lastAt = cpu, now
	if prevAt.IsZero() || !now.After(prevAt) {
		// Baseline: a percentage needs an interval to divide by.
		s.percent = nil
		return
	}
	delta := cpu - prevCPU
	if delta < 0 {
		// A shrinking reading means the counter restarted; rebase like the
		// direct-traffic accountant does rather than report a negative usage.
		s.percent = nil
		return
	}
	percent := float64(delta) / float64(now.Sub(prevAt)) * 100
	s.percent = &percent
}

// cpuPercent returns the current reading, or nil while it is unmeasurable.
func (s *processCPUStats) cpuPercent() *float64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.percent == nil {
		return nil
	}
	value := *s.percent
	return &value
}

// ProcessCPUPercent reports dae's CPU usage over the latest sampling interval as
// a percentage of one CPU. Nil while a second sample has not been taken yet.
func (c *ControlPlane) ProcessCPUPercent() *float64 {
	if c == nil {
		return nil
	}
	return c.processCPU.cpuPercent()
}
