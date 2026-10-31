/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
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

const (
	// memorySampleInterval is the nominal spacing of memory history samples.
	memorySampleInterval = time.Second
	// maxMemoryHistorySeconds bounds the memory history ring. The contract's
	// memory history window uses the same 3600s ceiling as traffic history.
	maxMemoryHistorySeconds = 3600
	// ebpfMemorySampleInterval throttles the /proc fdinfo scan; it is much
	// more expensive than reading the cgroup counters.
	ebpfMemorySampleInterval = 10 * time.Second
)

// CgroupMemoryEvents are the cgroup v2 memory.events counters.
type CgroupMemoryEvents struct {
	High    *uint64
	OOM     *uint64
	OOMKill *uint64
}

// CgroupMemorySnapshot is the cgroup v2 memory reading for this process.
type CgroupMemorySnapshot struct {
	Scope        string
	CurrentBytes *uint64
	LimitBytes   *uint64
	// LimitUnlimited is set when memory.max exists but reads "max". The limit is
	// then reported as nil (there is no byte value to report) while still
	// counting as a known metric, so a client can render "unlimited" instead of
	// "unknown".
	LimitUnlimited bool
	Events         *CgroupMemoryEvents
}

// KernelMemorySnapshot is the kernel memory charged to this process's eBPF
// objects.
type KernelMemorySnapshot struct {
	EbpfBytes *uint64
	SampledAt time.Time
}

// MemorySnapshot is one point-in-time memory reading.
type MemorySnapshot struct {
	ObservedAt time.Time
	RSSBytes   *uint64
	Cgroup     *CgroupMemorySnapshot
	Kernel     *KernelMemorySnapshot
}

// MemorySample is one retained memory history point.
type MemorySample struct {
	SampledAt          time.Time
	RSSBytes           *uint64
	CgroupCurrentBytes *uint64
	KernelEbpfBytes    *uint64
}

// MemoryHistorySnapshot is a thinned, time-filtered history window.
type MemoryHistorySnapshot struct {
	ObservedAt          time.Time
	WindowSeconds       int
	SampledEverySeconds float64
	Samples             []MemorySample
	Metrics             []string
}

type memoryStats struct {
	mu sync.Mutex

	// now is time.Now in production; tests replace it to drive samples.
	now func() time.Time
	// procSelf is "/proc/self" in production and a fixture directory in tests.
	procSelf string

	samples       []MemorySample
	historyStart  int
	historyLength int

	metrics []string

	ebpfBytes *uint64
	ebpfAt    time.Time
}

func newMemoryStats() *memoryStats {
	return &memoryStats{now: time.Now, procSelf: "/proc/self"}
}

func maxMemoryHistorySamples() int {
	return int((time.Duration(maxMemoryHistorySeconds) * time.Second) / memorySampleInterval)
}

// readMemorySnapshot reads one memory point. Every field is optional: a
// missing /proc or cgroup file leaves that metric nil instead of failing the
// snapshot.
func readMemorySnapshot(procSelf string) MemorySnapshot {
	snapshot := MemorySnapshot{ObservedAt: time.Now()}
	if rss, ok := readProcessRSS(filepath.Join(procSelf, "status")); ok {
		snapshot.RSSBytes = &rss
	}
	if cgroup := readCgroupMemory(procSelf); cgroup != nil {
		snapshot.Cgroup = cgroup
	}
	return snapshot
}

func readProcessRSS(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) < 2 || fields[1] != "kB" {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

func readCgroupMemory(procSelf string) *CgroupMemorySnapshot {
	directory, ok := cgroupDirectory(procSelf)
	if !ok {
		return nil
	}
	snapshot := &CgroupMemorySnapshot{Scope: cgroupScope(directory)}

	current, currentOK := readUintFile(filepath.Join(directory, "memory.current"))
	limit, unlimited, limitOK := readMemoryMax(filepath.Join(directory, "memory.max"))
	events := readCgroupEvents(filepath.Join(directory, "memory.events"))
	if currentOK {
		snapshot.CurrentBytes = &current
	}
	if limitOK {
		if unlimited {
			snapshot.LimitUnlimited = true
		} else {
			snapshot.LimitBytes = &limit
		}
	}
	if events != nil {
		snapshot.Events = events
	}
	if snapshot.CurrentBytes == nil && snapshot.LimitBytes == nil && snapshot.Events == nil {
		return nil
	}
	return snapshot
}

func readUintFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value := strings.TrimSpace(string(data))
	if value == "" || value == "max" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// readMemoryMax reads memory.max, which uses the literal "max" for an
// unlimited cgroup. That case is reported separately from a missing file: the
// first means "no limit", the second means "this system does not report
// limits".
func readMemoryMax(path string) (value uint64, unlimited bool, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false, false
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "max" {
		return 0, true, true
	}
	if trimmed == "" {
		return 0, false, false
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, false, false
	}
	return parsed, false, true
}

func readCgroupEvents(path string) *CgroupMemoryEvents {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	values := make(map[string]uint64, 3)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "high", "oom", "oom_kill":
			if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				values[fields[0]] = value
			}
		}
	}
	if len(values) == 0 {
		return nil
	}
	events := &CgroupMemoryEvents{}
	if value, ok := values["high"]; ok {
		events.High = &value
	}
	if value, ok := values["oom"]; ok {
		events.OOM = &value
	}
	if value, ok := values["oom_kill"]; ok {
		events.OOMKill = &value
	}
	return events
}

// cgroupDirectory resolves the cgroup v2 directory of this process from
// /proc/self/cgroup and the cgroup2 mount in /proc/self/mountinfo.
func cgroupDirectory(procSelf string) (string, bool) {
	membership, err := os.ReadFile(filepath.Join(procSelf, "cgroup"))
	if err != nil {
		return "", false
	}
	member := ""
	for _, line := range strings.Split(string(membership), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			member = strings.TrimSpace(rest)
			break
		}
	}
	if !strings.HasPrefix(member, "/") {
		return "", false
	}
	mountinfo, err := os.ReadFile(filepath.Join(procSelf, "mountinfo"))
	if err != nil {
		return "", false
	}
	type candidate struct {
		depth int
		path  string
	}
	var best candidate
	for _, line := range strings.Split(string(mountinfo), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		if fields := strings.Fields(right); len(fields) == 0 || fields[0] != "cgroup2" {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) < 5 {
			continue
		}
		root, ok := unescapeMountPath(fields[3])
		if !ok {
			continue
		}
		mount, ok := unescapeMountPath(fields[4])
		if !ok {
			continue
		}
		relative, ok := relativeCgroupPath(member, root)
		if !ok {
			continue
		}
		depth := strings.Count(root, "/")
		if depth >= best.depth {
			best = candidate{depth: depth, path: filepath.Join(mount, relative)}
		}
	}
	if best.path == "" {
		return "", false
	}
	return best.path, true
}

// relativeCgroupPath returns the part of member below root, with a leading
// slash, and requires a path boundary so "/a/b" does not match "/a/bc".
func relativeCgroupPath(member, root string) (string, bool) {
	if member == root {
		return "", true
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	if !strings.HasPrefix(member, prefix) {
		return "", false
	}
	return member[len(prefix)-1:], true
}

func unescapeMountPath(value string) (string, bool) {
	if !strings.HasPrefix(value, "/") {
		return "", false
	}
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value), true
}

// cgroupScope reports service only when dae is alone in a leaf cgroup, so the
// cgroup's memory is dae's own rather than shared with other processes.
func cgroupScope(directory string) string {
	procs, err := os.ReadFile(filepath.Join(directory, "cgroup.procs"))
	if err != nil {
		return "unknown"
	}
	lines := strings.Fields(string(procs))
	if len(lines) == 0 {
		return "unknown"
	}
	if len(lines) != 1 || lines[0] != strconv.Itoa(os.Getpid()) {
		return "shared"
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "unknown"
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return "shared"
		}
	}
	return "service"
}

// readEbpfBytes sums the memlock charged to this process's own BPF maps and
// programs, once per kernel object, using /proc fdinfo. It needs no BTF.
func readEbpfBytes(procSelf string) (uint64, bool) {
	fdDir := filepath.Join(procSelf, "fd")
	fdInfoDir := filepath.Join(procSelf, "fdinfo")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0, false
	}
	objects := make(map[bpfFdInfoKey]uint64)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if target != "anon_inode:bpf-map" && target != "anon_inode:bpf-prog" {
			continue
		}
		info, err := os.ReadFile(filepath.Join(fdInfoDir, entry.Name()))
		if err != nil {
			continue
		}
		key, memlock, ok := parseBpfFdInfo(string(info))
		if !ok {
			continue
		}
		objects[key] = memlock
	}
	// A readable fd table with no BPF objects means zero charged memory, not
	// an unknown reading; only an unreadable fd table is unknown.
	if len(objects) == 0 {
		return 0, true
	}
	var total uint64
	for _, memlock := range objects {
		total += memlock
	}
	return total, true
}

type bpfFdInfoKey struct {
	kind string
	id   uint64
}

func parseBpfFdInfo(info string) (key bpfFdInfoKey, memlock uint64, ok bool) {
	memlockSeen := false
	for _, line := range strings.Split(info, "\n") {
		switch {
		case strings.HasPrefix(line, "map_type:"):
			key.kind = "map"
		case strings.HasPrefix(line, "prog_type:"):
			key.kind = "prog"
		case strings.HasPrefix(line, "map_id:"), strings.HasPrefix(line, "prog_id:"):
			_, value, _ := strings.Cut(line, ":")
			id, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return key, 0, false
			}
			key.id = id
		case strings.HasPrefix(line, "memlock:"):
			_, value, _ := strings.Cut(line, ":")
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return key, 0, false
			}
			memlock = parsed
			memlockSeen = true
		}
	}
	if key.kind == "" || key.id == 0 || !memlockSeen {
		return key, 0, false
	}
	return key, memlock, true
}

// sample reads and records one memory point and learns any metric that became
// observable so capabilities can advertise it.
func (s *memoryStats) sample() {
	if s == nil {
		return
	}
	now := s.clock()
	snapshot := readMemorySnapshot(s.procSelf)
	ebpfBytes, ebpfAt := s.cachedEbpfBytes(now)
	snapshot.Kernel = &KernelMemorySnapshot{EbpfBytes: ebpfBytes, SampledAt: ebpfAt}

	sample := MemorySample{SampledAt: now, RSSBytes: snapshot.RSSBytes}
	if snapshot.Cgroup != nil {
		sample.CgroupCurrentBytes = snapshot.Cgroup.CurrentBytes
	}
	sample.KernelEbpfBytes = snapshot.Kernel.EbpfBytes

	s.mu.Lock()
	defer s.mu.Unlock()
	s.learnMetricsLocked(snapshot)
	s.pushLocked(sample, now)
}

// cachedEbpfBytes returns the eBPF bytes and the time they were actually read,
// so the reported sampled_at never claims a cached value is fresher than it is.
func (s *memoryStats) cachedEbpfBytes(now time.Time) (*uint64, time.Time) {
	s.mu.Lock()
	cached, cachedAt := s.ebpfBytes, s.ebpfAt
	s.mu.Unlock()
	if !cachedAt.IsZero() && now.Sub(cachedAt) < ebpfMemorySampleInterval {
		if cached == nil {
			return nil, time.Time{}
		}
		return cached, cachedAt
	}
	bytes, ok := readEbpfBytes(s.procSelf)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.ebpfBytes = &bytes
	}
	// Throttle retries after a failure too; otherwise a datapath without
	// reachable fdinfo would rescan /proc on every sample.
	s.ebpfAt = now
	if s.ebpfBytes == nil {
		return nil, time.Time{}
	}
	return s.ebpfBytes, s.ebpfAt
}

func (s *memoryStats) learnMetricsLocked(snapshot MemorySnapshot) {
	learn := func(metric string) {
		for _, existing := range s.metrics {
			if existing == metric {
				return
			}
		}
		s.metrics = append(s.metrics, metric)
	}
	if snapshot.RSSBytes != nil {
		learn("process.rss_bytes")
	}
	if snapshot.Cgroup != nil {
		if snapshot.Cgroup.CurrentBytes != nil {
			learn("cgroup.current_bytes")
		}
		if snapshot.Cgroup.LimitBytes != nil || snapshot.Cgroup.LimitUnlimited {
			learn("cgroup.limit_bytes")
		}
		if snapshot.Cgroup.Events != nil {
			if snapshot.Cgroup.Events.High != nil {
				learn("cgroup.events.high")
			}
			if snapshot.Cgroup.Events.OOM != nil {
				learn("cgroup.events.oom")
			}
			if snapshot.Cgroup.Events.OOMKill != nil {
				learn("cgroup.events.oom_kill")
			}
		}
	}
	if snapshot.Kernel != nil && snapshot.Kernel.EbpfBytes != nil {
		learn("kernel.ebpf_bytes")
	}
}

func (s *memoryStats) pushLocked(sample MemorySample, now time.Time) {
	cutoff := now.Add(-time.Duration(maxMemoryHistorySeconds) * time.Second)
	for s.historyLength > 0 {
		oldest := s.samples[s.historyStart]
		if !oldest.SampledAt.Before(cutoff) {
			break
		}
		s.historyStart = (s.historyStart + 1) % len(s.samples)
		s.historyLength--
	}
	if s.samples == nil {
		s.samples = make([]MemorySample, maxMemoryHistorySamples())
	}
	if s.historyLength < len(s.samples) {
		index := (s.historyStart + s.historyLength) % len(s.samples)
		s.samples[index] = sample
		s.historyLength++
		return
	}
	s.samples[s.historyStart] = sample
	s.historyStart = (s.historyStart + 1) % len(s.samples)
}

func (s *memoryStats) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

// snapshotHistory returns the retained samples inside the requested window,
// thinned to maxPoints with the same every-Nth-from-newest rule as traffic
// history.
func (s *memoryStats) snapshotHistory(windowSeconds, maxPoints int, now time.Time) MemoryHistorySnapshot {
	if s == nil {
		return MemoryHistorySnapshot{ObservedAt: now, WindowSeconds: windowSeconds, SampledEverySeconds: memorySampleInterval.Seconds()}
	}
	if windowSeconds <= 0 {
		windowSeconds = maxMemoryHistorySeconds
	}
	if maxPoints <= 0 {
		maxPoints = 180
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	start := now.Add(-time.Duration(windowSeconds) * time.Second)
	samples := make([]MemorySample, 0, s.historyLength)
	for i := 0; i < s.historyLength; i++ {
		sample := s.samples[(s.historyStart+i)%len(s.samples)]
		if sample.SampledAt.Before(start) || sample.SampledAt.After(now) {
			continue
		}
		samples = append(samples, sample)
	}
	samples = thinMemorySamples(samples, maxPoints)

	every := memorySampleInterval.Seconds()
	if len(samples) >= 2 {
		span := samples[len(samples)-1].SampledAt.Sub(samples[0].SampledAt)
		if span > 0 {
			every = span.Seconds() / float64(len(samples)-1)
		}
	}
	metrics := append([]string(nil), s.metrics...)
	return MemoryHistorySnapshot{
		ObservedAt:          now,
		WindowSeconds:       windowSeconds,
		SampledEverySeconds: every,
		Samples:             samples,
		Metrics:             metrics,
	}
}

func thinMemorySamples(samples []MemorySample, maxPoints int) []MemorySample {
	if maxPoints <= 0 || len(samples) <= maxPoints {
		return samples
	}
	stride := (len(samples) + maxPoints - 1) / maxPoints
	result := make([]MemorySample, 0, maxPoints)
	for i := len(samples) - 1; i >= 0; i -= stride {
		result = append(result, samples[i])
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

// memorySnapshot projects the latest reading for the API.
func (s *memoryStats) memorySnapshot() MemorySnapshot {
	if s == nil {
		return MemorySnapshot{ObservedAt: time.Now()}
	}
	now := s.clock()
	snapshot := readMemorySnapshot(s.procSelf)
	snapshot.ObservedAt = now
	ebpfBytes, ebpfAt := s.cachedEbpfBytes(now)
	snapshot.Kernel = &KernelMemorySnapshot{EbpfBytes: ebpfBytes, SampledAt: ebpfAt}
	s.mu.Lock()
	s.learnMetricsLocked(snapshot)
	s.mu.Unlock()
	return snapshot
}

func (s *memoryStats) metricNames() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.metrics...)
}

// startMemorySampler records one memory point immediately, then samples at
// the history interval until the plane context is cancelled. The immediate
// sample makes capabilities advertise the readable metrics without waiting
// for the first tick.
//
// CPU usage rides the same ticker: it is a delta between two readings, so it
// needs a steady interval of its own, and one second is what the contract calls
// the server's sampling interval. The first tick only establishes the baseline.
func (c *ControlPlane) startMemorySampler() {
	if c == nil || c.memoryStats == nil {
		return
	}
	c.memoryStats.sample()
	c.processCPU.sample(c.memoryStats.clock())
	go func() {
		ticker := time.NewTicker(memorySampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				now := c.memoryStats.clock()
				c.memoryStats.sample()
				c.processCPU.sample(now)
			}
		}
	}()
}

// MemorySnapshot returns the latest process memory reading.
func (c *ControlPlane) MemorySnapshot() MemorySnapshot {
	if c == nil {
		return MemorySnapshot{ObservedAt: time.Now()}
	}
	return c.memoryStats.memorySnapshot()
}

// MemoryHistory returns the retained memory samples inside the window.
func (c *ControlPlane) MemoryHistory(windowSeconds, maxPoints int) MemoryHistorySnapshot {
	if c == nil {
		now := time.Now()
		return MemoryHistorySnapshot{ObservedAt: now, WindowSeconds: windowSeconds, SampledEverySeconds: memorySampleInterval.Seconds()}
	}
	return c.memoryStats.snapshotHistory(windowSeconds, maxPoints, c.memoryStats.clock())
}

// MemoryMetrics returns the memory metrics this process can observe.
func (c *ControlPlane) MemoryMetrics() []string {
	if c == nil {
		return nil
	}
	return c.memoryStats.metricNames()
}
