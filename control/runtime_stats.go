/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
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

// RuntimeSampleInterval is the recorder interval of traffic history samples.
const RuntimeSampleInterval = runtimeBucketDuration

// RuntimeTrafficSample contains one upload/download rate point.
type RuntimeTrafficSample struct {
	Timestamp    time.Time
	UploadRate   uint64
	DownloadRate uint64
}

// RuntimeStatsSnapshot preserves the traffic-latency branch's exported API.
type RuntimeStatsSnapshot struct {
	UpdatedAt     time.Time
	UploadRate    uint64
	DownloadRate  uint64
	UploadTotal   uint64
	DownloadTotal uint64
	// UserspaceUploadTotal/UserspaceDownloadTotal are the relay and DNS bytes.
	// DirectUploadTotal/DirectDownloadTotal are the kernel pass-through bytes
	// that never reach userspace. Their sum is UploadTotal/DownloadTotal, so the
	// two planes stay separable without changing the total.
	UserspaceUploadTotal   uint64
	UserspaceDownloadTotal uint64
	DirectUploadTotal      uint64
	DirectDownloadTotal    uint64
	ActiveConnections      int
	UDPSessions            int
	Samples                []RuntimeTrafficSample
}

type runtimeBucket struct {
	Timestamp     time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	Duration      time.Duration
}

type runtimeStats struct {
	mu sync.Mutex

	// now is time.Now in production; tests replace it to drive a simulated
	// clock through record() and snapshot().
	now func() time.Time

	currentBucketStartUnixNano atomic.Int64
	currentUploadBytes         atomic.Uint64
	currentDownloadBytes       atomic.Uint64

	uploadTotal   atomic.Uint64
	downloadTotal atomic.Uint64

	// Per-plane splits of the lifetime totals. Every byte lands in exactly one
	// plane, so userspace+direct always equals uploadTotal/downloadTotal.
	userspaceUploadBytes   atomic.Uint64
	userspaceDownloadBytes atomic.Uint64
	directUploadBytes      atomic.Uint64
	directDownloadBytes    atomic.Uint64

	history      []runtimeBucket
	historyStart int
	historyLen   int
}

var (
	globalRuntimeStats = newRuntimeStats()
	activeRuntimeStats atomic.Pointer[runtimeStats]
	// lastPublishedRuntimeStats keeps the previous generation's store reachable
	// for the totals handoff even while no store is active (a reload gap).
	lastPublishedRuntimeStats atomic.Pointer[runtimeStats]
)

func newRuntimeStats() *runtimeStats {
	return &runtimeStats{now: time.Now}
}

func (s *runtimeStats) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

func maxRuntimeHistoryBuckets() int {
	return int((time.Duration(maxRuntimeHistorySeconds) * time.Second) / runtimeBucketDuration)
}

func currentRuntimeStatsStore() *runtimeStats {
	if active := activeRuntimeStats.Load(); active != nil {
		return active
	}
	return globalRuntimeStats
}

func publishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	if prev := lastPublishedRuntimeStats.Load(); prev != nil {
		s.inheritTotalsFrom(prev)
	}
	activeRuntimeStats.Store(s)
	lastPublishedRuntimeStats.Store(s)
}

// inheritTotalsFrom carries the process-lifetime byte totals across a
// generation handoff.
//
// A reload builds a fresh generation-local store. Without this the reported
// totals dropped to zero on every reload while runtime/outbounds kept counting
// in its process-level registry, so the two resources disagreed by the whole
// process history - which reads as "the API numbers are wrong".
func (s *runtimeStats) inheritTotalsFrom(prev *runtimeStats) {
	if s == nil || prev == nil || s == prev {
		return
	}
	s.uploadTotal.Add(prev.uploadTotal.Load())
	s.downloadTotal.Add(prev.downloadTotal.Load())
	s.userspaceUploadBytes.Add(prev.userspaceUploadBytes.Load())
	s.userspaceDownloadBytes.Add(prev.userspaceDownloadBytes.Load())
	s.directUploadBytes.Add(prev.directUploadBytes.Load())
	s.directDownloadBytes.Add(prev.directDownloadBytes.Load())
}

func unpublishRuntimeStatsStore(s *runtimeStats) {
	if s == nil {
		return
	}
	activeRuntimeStats.CompareAndSwap(s, nil)
}

// RecordUploadTraffic records upload bytes into the global runtime history.
func RecordUploadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(uint64(n), 0)
	}
}

// RecordDownloadTraffic records download bytes into the global runtime history.
func RecordDownloadTraffic(n int64) {
	if n <= 0 {
		return
	}
	if store := currentRuntimeStatsStore(); store != nil {
		store.record(0, uint64(n))
	}
}

func (c *ControlPlane) publishRuntimeStats() {
	if c == nil {
		return
	}
	publishRuntimeStatsStore(c.runtimeStats)
}

func (c *ControlPlane) unpublishRuntimeStats() {
	if c == nil {
		return
	}
	unpublishRuntimeStatsStore(c.runtimeStats)
}

func (s *runtimeStats) record(upload uint64, download uint64) {
	s.recordForPlane(upload, download, true)
}

// recordDirect folds kernel pass-through bytes into the same history and totals
// as the relay while keeping them attributable under traffic.planes.
func (s *runtimeStats) recordDirect(upload uint64, download uint64) {
	s.recordForPlane(upload, download, false)
}

// recordForPlane is the single writer of the bucket, the lifetime totals and
// the plane split, so the three can never drift apart.
func (s *runtimeStats) recordForPlane(upload uint64, download uint64, userspace bool) {
	if s == nil || (upload == 0 && download == 0) {
		return
	}
	// Rotate here, not only in snapshot: a dashboard polls at its own cadence,
	// so bytes recorded between two polls would otherwise all land in the
	// first finished bucket. The one-second rate would then be scaled by that
	// bucket's share of the window and under-report - or drop to zero once the
	// bucket leaves the window.
	s.advanceBucket(s.clock())
	if upload > 0 {
		s.currentUploadBytes.Add(upload)
		s.uploadTotal.Add(upload)
		if userspace {
			s.userspaceUploadBytes.Add(upload)
		} else {
			s.directUploadBytes.Add(upload)
		}
	}
	if download > 0 {
		s.currentDownloadBytes.Add(download)
		s.downloadTotal.Add(download)
		if userspace {
			s.userspaceDownloadBytes.Add(download)
		} else {
			s.directDownloadBytes.Add(download)
		}
	}
}

// startRoller was removed: rollLocked is fully lazy. The bucket window only
// advances when traffic is recorded or a snapshot is requested, so no
// periodic goroutine is needed. An empty-window ticker previously woke up
// ~4x/second on idle just to perform a no-op rotation.

// advanceBucket rotates the in-flight bucket once its boundary has passed.
// The common case is one atomic load and compare; only a crossing takes the
// lock, so the burst path never contends with a reader.
func (s *runtimeStats) advanceBucket(now time.Time) {
	if s == nil {
		return
	}
	start := timeFromUnixNano(s.currentBucketStartUnixNano.Load())
	if !start.IsZero() && !bucketStart(now).After(start) {
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

	// Include the in-flight bucket when it has actually spanned time. A
	// zero-length bucket would otherwise be counted as a full interval in the
	// rate denominator and in the sample series, dragging both down (or
	// fabricating a zero sample) whenever a snapshot lands exactly on a
	// boundary.
	// History carries only completed intervals: the in-flight bucket's rate is
	// an instantaneous reading whose span shrinks to nothing near a boundary,
	// which would show up as a spike at the end of every chart.
	completedBuckets := len(buckets)

	currentBucketStart := s.currentBucketStartLocked()
	if currentDuration := now.Sub(currentBucketStart); currentDuration > 0 {
		buckets = append(buckets, runtimeBucket{
			Timestamp:     now,
			UploadBytes:   s.currentUploadBytes.Load(),
			DownloadBytes: s.currentDownloadBytes.Load(),
			Duration:      currentDuration,
		})
	}

	uploadRate, downloadRate := ratesFromBuckets(buckets, now, runtimeRateWindow)

	return RuntimeStatsSnapshot{
		UpdatedAt:              now,
		UploadRate:             uploadRate,
		DownloadRate:           downloadRate,
		UploadTotal:            s.uploadTotal.Load(),
		DownloadTotal:          s.downloadTotal.Load(),
		UserspaceUploadTotal:   s.userspaceUploadBytes.Load(),
		UserspaceDownloadTotal: s.userspaceDownloadBytes.Load(),
		DirectUploadTotal:      s.directUploadBytes.Load(),
		DirectDownloadTotal:    s.directDownloadBytes.Load(),
		ActiveConnections:      activeConnections,
		UDPSessions:            udpSessions,
		Samples:                thinRuntimeSamples(samplesFromBuckets(buckets[:completedBuckets]), maxPoints),
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
	// An idle gap longer than the retention ring cannot be materialized bucket
	// by bucket; jump to the oldest bucket that can still be retained so the
	// rotation stays bounded after a long pause.
	if gap := targetBucketStart.Sub(currentBucketStart); gap > time.Duration(maxRuntimeHistoryBuckets())*runtimeBucketDuration {
		currentBucketStart = targetBucketStart.Add(-time.Duration(maxRuntimeHistoryBuckets()) * runtimeBucketDuration)
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

// thinRuntimeSamples selects every Nth stored sample backwards from the newest
// so at most maxPoints are returned. The contract asks for decimation with the
// original timestamps and rates preserved: aggregating a bucket (for example
// with its maximum) would fabricate spikes the recorder never measured.
func thinRuntimeSamples(samples []RuntimeTrafficSample, maxPoints int) []RuntimeTrafficSample {
	if maxPoints <= 0 || len(samples) <= maxPoints {
		return samples
	}
	stride := (len(samples) + maxPoints - 1) / maxPoints

	result := make([]RuntimeTrafficSample, 0, maxPoints)
	for i := len(samples) - 1; i >= 0; i -= stride {
		result = append(result, samples[i])
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
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
