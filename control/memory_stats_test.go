/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// writeMemoryFixture lays out a /proc/self-like tree with a cgroup2 mount.
func writeMemoryFixture(t *testing.T) (procSelf, cgroupDir string) {
	t.Helper()
	procSelf = t.TempDir()
	cgroupMount := t.TempDir()
	cgroupDir = filepath.Join(cgroupMount, "svc")
	if err := os.MkdirAll(cgroupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(procSelf, "status"), "Name:\tdae\nVmRSS:\t  1234 kB\n")
	writeFile(t, filepath.Join(procSelf, "cgroup"), "0::/svc\n")
	writeFile(t, filepath.Join(procSelf, "mountinfo"),
		"36 25 0:32 / "+cgroupMount+" rw,nosuid - cgroup2 cgroup rw\n")
	writeFile(t, filepath.Join(cgroupDir, "memory.current"), "8589934592\n")
	writeFile(t, filepath.Join(cgroupDir, "memory.max"), "17179869184\n")
	writeFile(t, filepath.Join(cgroupDir, "memory.events"),
		"low 0\nhigh 3\noom 4\noom_kill 5\n")
	writeFile(t, filepath.Join(cgroupDir, "cgroup.procs"), strconv.Itoa(os.Getpid())+"\n")
	return procSelf, cgroupDir
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadMemorySnapshot(t *testing.T) {
	procSelf, _ := writeMemoryFixture(t)

	snapshot := readMemorySnapshot(procSelf)
	if snapshot.RSSBytes == nil || *snapshot.RSSBytes != 1234*1024 {
		t.Fatalf("rss = %v, want %d", snapshot.RSSBytes, 1234*1024)
	}
	if snapshot.Cgroup == nil {
		t.Fatal("cgroup reading is missing")
	}
	if snapshot.Cgroup.Scope != "service" {
		t.Fatalf("scope = %q, want service", snapshot.Cgroup.Scope)
	}
	if snapshot.Cgroup.CurrentBytes == nil || *snapshot.Cgroup.CurrentBytes != 8589934592 {
		t.Fatalf("current = %v", snapshot.Cgroup.CurrentBytes)
	}
	if snapshot.Cgroup.LimitBytes == nil || *snapshot.Cgroup.LimitBytes != 17179869184 {
		t.Fatalf("limit = %v", snapshot.Cgroup.LimitBytes)
	}
	if snapshot.Cgroup.Events == nil || snapshot.Cgroup.Events.OOMKill == nil || *snapshot.Cgroup.Events.OOMKill != 5 {
		t.Fatalf("events = %#v", snapshot.Cgroup.Events)
	}
}

func TestReadMemorySnapshotMissingFilesStayNil(t *testing.T) {
	snapshot := readMemorySnapshot(t.TempDir())
	if snapshot.RSSBytes != nil || snapshot.Cgroup != nil {
		t.Fatalf("snapshot = %#v, want nil fields", snapshot)
	}
}

func TestCgroupScopeSharedWhenOtherProcessesPresent(t *testing.T) {
	procSelf, cgroupDir := writeMemoryFixture(t)
	writeFile(t, filepath.Join(cgroupDir, "cgroup.procs"), strconv.Itoa(os.Getpid())+"\n999999\n")

	snapshot := readMemorySnapshot(procSelf)
	if snapshot.Cgroup == nil || snapshot.Cgroup.Scope != "shared" {
		t.Fatalf("scope = %#v, want shared", snapshot.Cgroup)
	}
}

func TestMemoryHistoryWindowAndThinning(t *testing.T) {
	procSelf, _ := writeMemoryFixture(t)
	stats := newMemoryStats()
	stats.procSelf = procSelf
	base := time.Unix(1700000000, 0)
	for i := 0; i < 20; i++ {
		stats.now = func() time.Time { return base.Add(time.Duration(i) * time.Second) }
		stats.sample()
	}

	history := stats.snapshotHistory(10, 5, base.Add(19*time.Second))
	if len(history.Samples) == 0 || len(history.Samples) > 5 {
		t.Fatalf("samples = %d, want 1..5 (stride thinning keeps every Nth)", len(history.Samples))
	}
	for i := 1; i < len(history.Samples); i++ {
		if !history.Samples[i].SampledAt.After(history.Samples[i-1].SampledAt) {
			t.Fatalf("samples are not oldest-first: %v then %v",
				history.Samples[i-1].SampledAt, history.Samples[i].SampledAt)
		}
	}
	if history.Samples[0].SampledAt.Before(base.Add(9 * time.Second)) {
		t.Fatalf("oldest sample = %v, want inside the 10s window", history.Samples[0].SampledAt)
	}
	if history.WindowSeconds != 10 {
		t.Fatalf("window = %d, want 10", history.WindowSeconds)
	}
	// Every-third thinning leaves ~3s between retained samples.
	if history.SampledEverySeconds < 2 || history.SampledEverySeconds > 4 {
		t.Fatalf("sampled_every = %v, want ~3", history.SampledEverySeconds)
	}
	if len(history.Metrics) == 0 || history.Metrics[0] != "process.rss_bytes" {
		t.Fatalf("metrics = %#v", history.Metrics)
	}
}

func TestMemoryHistoryEmptyWindowUsesRecorderInterval(t *testing.T) {
	stats := newMemoryStats()
	stats.procSelf = t.TempDir()
	now := time.Unix(1700000000, 0)
	history := stats.snapshotHistory(60, 30, now)
	if len(history.Samples) != 0 {
		t.Fatalf("samples = %d, want 0", len(history.Samples))
	}
	if history.SampledEverySeconds != memorySampleInterval.Seconds() {
		t.Fatalf("sampled_every = %v, want %v", history.SampledEverySeconds, memorySampleInterval.Seconds())
	}
}

func TestThinMemorySamplesKeepsNewest(t *testing.T) {
	samples := make([]MemorySample, 6)
	for i := range samples {
		samples[i].SampledAt = time.Unix(int64(i), 0)
	}
	thinned := thinMemorySamples(samples, 3)
	if len(thinned) != 3 {
		t.Fatalf("thinned = %d, want 3", len(thinned))
	}
	if !thinned[len(thinned)-1].SampledAt.Equal(samples[len(samples)-1].SampledAt) {
		t.Fatalf("newest sample was dropped: %v", thinned)
	}
}

func TestParseBpfFdInfo(t *testing.T) {
	key, memlock, ok := parseBpfFdInfo("map_type:\t2\nmap_id:\t42\nmemlock:\t8192\n")
	if !ok || key.kind != "map" || key.id != 42 || memlock != 8192 {
		t.Fatalf("parsed = %#v %d %v", key, memlock, ok)
	}
	if _, _, ok := parseBpfFdInfo("prog_type:\t1\n"); ok {
		t.Fatal("fdinfo without an id must not parse")
	}
}

func TestRelativeCgroupPathRequiresBoundary(t *testing.T) {
	cases := []struct {
		member, root, want string
		ok                 bool
	}{
		{"/a/b/c", "/a/b", "/c", true},
		{"/a/b", "/a/b", "", true},
		{"/a/bc/d", "/a/b", "", false},
		{"/svc", "/", "/svc", true},
	}
	for _, tc := range cases {
		got, ok := relativeCgroupPath(tc.member, tc.root)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("relativeCgroupPath(%q,%q) = (%q,%v), want (%q,%v)", tc.member, tc.root, got, ok, tc.want, tc.ok)
		}
	}
}

func TestReadEbpfBytesReportsZeroWithoutObjects(t *testing.T) {
	procSelf := t.TempDir()
	if err := os.Mkdir(filepath.Join(procSelf, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	bytes, ok := readEbpfBytes(procSelf)
	if !ok || bytes != 0 {
		t.Fatalf("readEbpfBytes = (%d,%v), want (0,true) for a readable fd table", bytes, ok)
	}
	if _, ok := readEbpfBytes(t.TempDir()); ok {
		t.Fatal("an unreadable /proc tree must report unknown")
	}
}
