/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRuntimeHistorySeconds = 60 * 60
	defaultRuntimeWindowSec  = 30 * 60
	defaultRuntimeMaxPoints  = 180
	runtimeBucketDuration    = 250 * time.Millisecond
	runtimeRateWindow        = time.Second
)

// RuntimeTrafficSample contains one upload/download rate point.
type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

// RuntimeStatsSnapshot preserves the traffic-latency branch's exported API.
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
	mu         sync.Mutex
	rollerOnce sync.Once

	currentBucketStartUnixNano atomic.Int64
	currentUploadBytes         atomic.Uint64
	currentDownloadBytes       atomic.Uint64

	uploadTotal   atomic.Uint64
	downloadTotal atomic.Uint64
	history       []runtimeBucket
	historyStart  int
	historyLen    int
}

var globalRuntimeStats = newRuntimeStats()

func newRuntimeStats() *runtimeStats {
	return &runtimeStats{}
}

func maxRuntimeHistoryBuckets() int {
	return int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
}

// RecordUploadTraffic records upload bytes into the global runtime history.
func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if globalRuntimeStats != nil {
		globalRuntimeStats.record(uint64(n), 0)
	}
}

// RecordDownloadTraffic records download bytes into the global runtime history.
func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if globalRuntimeStats != nil {
		globalRuntimeStats.record(0, uint64(n))
	}
}

// Deprecated: prefer (*ControlPlane).SnapshotRuntimeStats for per-instance stats.
// SnapshotRuntimeStats returns the current runtime traffic snapshot.
func SnapshotRuntimeStats(activeConnections int, udpSessions int, windowSec int, maxPoints int) RuntimeStatsSnapshot {
	if globalRuntimeStats == nil {
		return RuntimeStatsSnapshot{
			UpdatedAt:         time.Now(),
			ActiveConnections: activeConnections,
			UDPSessions:       udpSessions,
		}
	}
	return globalRuntimeStats.snapshot(activeConnections, udpSessions, windowSec, maxPoints, time.Now())
}

func (s *runtimeStats) record(upload uint64, download uint64) {
	if s == nil {
		return
	}
	if upload > 0 {
		s.currentUploadBytes.Add(upload)
		s.uploadTotal.Add(upload)
	}
	if download > 0 {
		s.currentDownloadBytes.Add(download)
		s.downloadTotal.Add(download)
	}
}

func (s *runtimeStats) startRoller(ctx context.Context) {
	if s == nil || ctx == nil {
		return
	}
	s.rollerOnce.Do(func() {
		s.roll(time.Now())
		go func() {
			ticker := time.NewTicker(runtimeBucketDuration)
			defer ticker.Stop()

			for {
				select {
				case now := <-ticker.C:
					s.roll(now)
				case <-ctx.Done():
					s.roll(time.Now())
					return
				}
			}
		}()
	})
}

func (s *runtimeStats) roll(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollLocked(now)
}

func (s *runtimeStats) snapshot(activeConnections int, udpSessions int, windowSec int, maxPoints int, now time.Time) RuntimeStatsSnapshot {
	if s == nil {
		return RuntimeStatsSnapshot{
			UpdatedAt:         now,
			ActiveConnections: activeConnections,
			UDPSessions:       udpSessions,
		}
	}
	if windowSec <= 0 {
		windowSec = defaultRuntimeWindowSec
	}
	if maxPoints <= 0 {
		maxPoints = defaultRuntimeMaxPoints
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rollLocked(now)

	startTime := now.Add(-time.Duration(windowSec) * time.Second)

	buckets := make([]runtimeBucket, 0, s.historyLen+1)
	for i := 0; i < s.historyLen; i++ {
		bucket := s.history[(s.historyStart+i)%len(s.history)]
		if !bucket.Timestamp.Before(startTime) {
			buckets = append(buckets, bucket)
		}
	}

	currentBucketStart := s.currentBucketStartLocked()
	currentDuration := now.Sub(currentBucketStart)
	if currentDuration <= 0 {
		currentDuration = runtimeBucketDuration
	}
	buckets = append(buckets, runtimeBucket{
		Timestamp:     now,
		UploadBytes:   s.currentUploadBytes.Load(),
		DownloadBytes: s.currentDownloadBytes.Load(),
		Duration:      currentDuration,
	})

	uploadRate, downloadRate := ratesFromBuckets(buckets, now, runtimeRateWindow)

	return RuntimeStatsSnapshot{
		UpdatedAt:         now,
		UploadRate:        uploadRate,
		DownloadRate:      downloadRate,
		UploadTotal:       s.uploadTotal.Load(),
		DownloadTotal:     s.downloadTotal.Load(),
		ActiveConnections: activeConnections,
		UDPSessions:       udpSessions,
		Samples:           bucketizeRuntimeSamples(samplesFromBuckets(buckets), maxPoints),
	}
}

func (s *runtimeStats) currentBucketStartLocked() time.Time {
	return timeFromUnixNano(s.currentBucketStartUnixNano.Load())
}

func (s *runtimeStats) rollLocked(now time.Time) {
	targetBucketStart := bucketStart(now)
	currentBucketStart := s.currentBucketStartLocked()
	if currentBucketStart.IsZero() {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}
	if !targetBucketStart.After(currentBucketStart) {
		return
	}

	uploadBytes := s.currentUploadBytes.Swap(0)
	downloadBytes := s.currentDownloadBytes.Swap(0)
	if uploadBytes == 0 && downloadBytes == 0 && s.historyLen == 0 {
		s.currentBucketStartUnixNano.Store(targetBucketStart.UnixNano())
		return
	}
	for nextBucketStart := currentBucketStart.Add(runtimeBucketDuration); !nextBucketStart.After(targetBucketStart); nextBucketStart = nextBucketStart.Add(runtimeBucketDuration) {
		s.pushHistoryBucket(runtimeBucket{
			Timestamp:     nextBucketStart,
			UploadBytes:   uploadBytes,
			DownloadBytes: downloadBytes,
			Duration:      runtimeBucketDuration,
		})
		uploadBytes = 0
		downloadBytes = 0
		currentBucketStart = nextBucketStart
		s.currentBucketStartUnixNano.Store(currentBucketStart.UnixNano())
	}
}

func (s *runtimeStats) pushHistoryBucket(bucket runtimeBucket) {
	if s == nil {
		return
	}
	if len(s.history) == 0 {
		s.history = make([]runtimeBucket, maxRuntimeHistoryBuckets())
	}
	if s.historyLen < len(s.history) {
		idx := (s.historyStart + s.historyLen) % len(s.history)
		s.history[idx] = bucket
		s.historyLen++
		return
	}
	s.history[s.historyStart] = bucket
	s.historyStart = (s.historyStart + 1) % len(s.history)
}

func timeFromUnixNano(unixNano int64) time.Time {
	if unixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *ControlPlane) runtimeStatsStore() *runtimeStats {
	if c == nil || c.runtimeStats == nil {
		return globalRuntimeStats
	}
	return c.runtimeStats
}

func (c *ControlPlane) runtimeUploadRecorder() func(int64) {
	return c.recordUploadTraffic
}

func (c *ControlPlane) runtimeDownloadRecorder() func(int64) {
	return c.recordDownloadTraffic
}

func (c *ControlPlane) recordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(uint64(n), 0)
}

func (c *ControlPlane) recordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	c.runtimeStatsStore().record(0, uint64(n))
}

func (c *ControlPlane) SnapshotRuntimeStats(windowSec int, maxPoints int) RuntimeStatsSnapshot {
	activeConnections := 0
	udpSessions := 0
	if c != nil {
		activeConnections = c.ActiveTCPConnections()
		udpSessions = DefaultUdpEndpointPool.Len()
	}
	return c.runtimeStatsStore().snapshot(activeConnections, udpSessions, windowSec, maxPoints, time.Now())
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
