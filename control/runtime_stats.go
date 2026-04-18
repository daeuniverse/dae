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
	runtimeBucketDuration    = 250 * time.Millisecond
	runtimeRateWindow        = time.Second
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

type runtimeBucket struct {
	Timestamp     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	Duration      time.Duration
}

type runtimeStats struct {
	mu sync.Mutex

	currentBucketStart time.Time
	currentUploadBytes uint64
	currentDownloadBytes uint64

	uploadTotal   uint64
	downloadTotal uint64
	history       []runtimeBucket
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

	s.advanceLocked(bucketStart(now))
	s.currentUploadBytes += upload
	s.currentDownloadBytes += download
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

	nowBucketStart := bucketStart(now)
	s.advanceLocked(nowBucketStart)

	startTime := now.Add(-time.Duration(windowSec) * time.Second)

	buckets := make([]runtimeBucket, 0, len(s.history)+1)
	for _, bucket := range s.history {
		if !bucket.Timestamp.Before(startTime) {
			buckets = append(buckets, bucket)
		}
	}

	currentDuration := now.Sub(s.currentBucketStart)
	if currentDuration <= 0 {
		currentDuration = runtimeBucketDuration
	}
	buckets = append(buckets, runtimeBucket{
		Timestamp:     now,
		UploadBytes:   s.currentUploadBytes,
		DownloadBytes: s.currentDownloadBytes,
		Duration:      currentDuration,
	})

	uploadRate, downloadRate := ratesFromBuckets(buckets, now, runtimeRateWindow)

	return RuntimeStatsSnapshot{
		UpdatedAt:         now,
		UploadRate:        uploadRate,
		DownloadRate:      downloadRate,
		UploadTotal:       s.uploadTotal,
		DownloadTotal:     s.downloadTotal,
		ActiveConnections: activeConnections,
		UDPSessions:       udpSessions,
		Samples:           bucketizeRuntimeSamples(samplesFromBuckets(buckets), maxPoints),
	}
}

func (s *runtimeStats) advanceLocked(targetBucketStart time.Time) {
	if s.currentBucketStart.IsZero() {
		s.currentBucketStart = targetBucketStart
		return
	}
	if !targetBucketStart.After(s.currentBucketStart) {
		return
	}

	for s.currentBucketStart.Before(targetBucketStart) {
		s.history = append(s.history, runtimeBucket{
			Timestamp:     s.currentBucketStart.Add(runtimeBucketDuration),
			UploadBytes:   s.currentUploadBytes,
			DownloadBytes: s.currentDownloadBytes,
			Duration:      runtimeBucketDuration,
		})
		maxHistoryBuckets := int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
		if len(s.history) > maxHistoryBuckets {
			s.history = append([]runtimeBucket(nil), s.history[len(s.history)-maxHistoryBuckets:]...)
		}
		s.currentBucketStart = s.currentBucketStart.Add(runtimeBucketDuration)
		s.currentUploadBytes = 0
		s.currentDownloadBytes = 0
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

func bucketStart(now time.Time) time.Time {
	return now.Truncate(runtimeBucketDuration)
}

func rateFromBytes(bytes uint64, duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(float64(bytes) * float64(time.Second) / float64(duration))
}

func samplesFromBuckets(buckets []runtimeBucket) []RuntimeTrafficSample {
	samples := make([]RuntimeTrafficSample, 0, len(buckets))
	for _, bucket := range buckets {
		samples = append(samples, RuntimeTrafficSample{
			Timestamp:    bucket.Timestamp,
			UploadRate:   rateFromBytes(bucket.UploadBytes, bucket.Duration),
			DownloadRate: rateFromBytes(bucket.DownloadBytes, bucket.Duration),
		})
	}
	return samples
}

func ratesFromBuckets(buckets []runtimeBucket, now time.Time, window time.Duration) (uploadRate uint64, downloadRate uint64) {
	if len(buckets) == 0 {
		return 0, 0
	}

	windowStart := now.Add(-window)
	var (
		totalUpload   uint64
		totalDownload uint64
		totalDuration time.Duration
	)

	for _, bucket := range buckets {
		bucketEnd := bucket.Timestamp
		bucketStart := bucketEnd.Add(-bucket.Duration)
		if !bucketEnd.After(windowStart) {
			continue
		}

		effectiveStart := bucketStart
		if effectiveStart.Before(windowStart) {
			effectiveStart = windowStart
		}
		effectiveDuration := bucketEnd.Sub(effectiveStart)
		if effectiveDuration <= 0 {
			continue
		}

		ratio := float64(effectiveDuration) / float64(bucket.Duration)
		totalUpload += uint64(float64(bucket.UploadBytes) * ratio)
		totalDownload += uint64(float64(bucket.DownloadBytes) * ratio)
		totalDuration += effectiveDuration
	}

	if totalDuration <= 0 {
		return 0, 0
	}

	return rateFromBytes(totalUpload, totalDuration), rateFromBytes(totalDownload, totalDuration)
}
