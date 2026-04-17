/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"sync"
	"time"
)

const (
	maxRuntimeHistorySeconds = 60 * 60
	defaultRuntimeWindowSec  = 30 * 60
	defaultRuntimeMaxPoints  = 180
)

type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

type RuntimeStatsSnapshot struct {
	UpdatedAt         time.Time
	UploadRate        uint64
	DownloadRate      uint64
	UploadTotal       uint64
	DownloadTotal     uint64
	ActiveConnections int
	UDPSessions       int
	Samples           []RuntimeTrafficSample
}

type runtimeStats struct {
	mu sync.Mutex

	currentSecond  int64
	currentUpload  uint64
	currentDownload uint64

	uploadTotal   uint64
	downloadTotal uint64
	history       []RuntimeTrafficSample
}

var globalRuntimeStats = &runtimeStats{}

func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	globalRuntimeStats.record(uint64(n), 0, time.Now())
}

func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	globalRuntimeStats.record(0, uint64(n), time.Now())
}

func SnapshotRuntimeStats(activeConnections int, udpSessions int, windowSec int, maxPoints int) RuntimeStatsSnapshot {
	return globalRuntimeStats.snapshot(activeConnections, udpSessions, windowSec, maxPoints, time.Now())
}

func (s *runtimeStats) record(upload uint64, download uint64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.advanceLocked(now.Unix())
	s.currentUpload += upload
	s.currentDownload += download
	s.uploadTotal += upload
	s.downloadTotal += download
}

func (s *runtimeStats) snapshot(activeConnections int, udpSessions int, windowSec int, maxPoints int, now time.Time) RuntimeStatsSnapshot {
	if windowSec <= 0 {
		windowSec = defaultRuntimeWindowSec
	}
	if maxPoints <= 0 {
		maxPoints = defaultRuntimeMaxPoints
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	nowSec := now.Unix()
	s.advanceLocked(nowSec)

	startSec := nowSec - int64(windowSec) + 1
	if startSec < 0 {
		startSec = 0
	}

	samples := make([]RuntimeTrafficSample, 0, len(s.history)+1)
	for _, sample := range s.history {
		if sample.Timestamp.Unix() >= startSec {
			samples = append(samples, sample)
		}
	}
	samples = append(samples, RuntimeTrafficSample{
		Timestamp:    time.Unix(nowSec, 0),
		UploadRate:   s.currentUpload,
		DownloadRate: s.currentDownload,
	})

	return RuntimeStatsSnapshot{
		UpdatedAt:         now,
		UploadRate:        s.currentUpload,
		DownloadRate:      s.currentDownload,
		UploadTotal:       s.uploadTotal,
		DownloadTotal:     s.downloadTotal,
		ActiveConnections: activeConnections,
		UDPSessions:       udpSessions,
		Samples:           bucketizeRuntimeSamples(samples, maxPoints),
	}
}

func (s *runtimeStats) advanceLocked(targetSecond int64) {
	if s.currentSecond == 0 {
		s.currentSecond = targetSecond
		return
	}
	if targetSecond <= s.currentSecond {
		return
	}

	for s.currentSecond < targetSecond {
		s.history = append(s.history, RuntimeTrafficSample{
			Timestamp:    time.Unix(s.currentSecond, 0),
			UploadRate:   s.currentUpload,
			DownloadRate: s.currentDownload,
		})
		if len(s.history) > maxRuntimeHistorySeconds {
			s.history = append([]RuntimeTrafficSample(nil), s.history[len(s.history)-maxRuntimeHistorySeconds:]...)
		}
		s.currentSecond++
		s.currentUpload = 0
		s.currentDownload = 0
	}
}

func bucketizeRuntimeSamples(samples []RuntimeTrafficSample, maxPoints int) []RuntimeTrafficSample {
	if len(samples) <= maxPoints {
		return samples
	}

	bucketSize := int(math.Ceil(float64(len(samples)) / float64(maxPoints)))
	result := make([]RuntimeTrafficSample, 0, maxPoints)

	for start := 0; start < len(samples); start += bucketSize {
		end := start + bucketSize
		if end > len(samples) {
			end = len(samples)
		}
		bucket := samples[start:end]
		last := bucket[len(bucket)-1]

		maxUpload := last.UploadRate
		maxDownload := last.DownloadRate
		for _, sample := range bucket[:len(bucket)-1] {
			if sample.UploadRate > maxUpload {
				maxUpload = sample.UploadRate
			}
			if sample.DownloadRate > maxDownload {
				maxDownload = sample.DownloadRate
			}
		}

		result = append(result, RuntimeTrafficSample{
			Timestamp:    last.Timestamp,
			UploadRate:   maxUpload,
			DownloadRate: maxDownload,
		})
	}

	return result
}
