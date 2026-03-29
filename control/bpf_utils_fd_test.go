//go:build linux && dae_bpf_map_tests
// +build linux,dae_bpf_map_tests

package control

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestNewLpmMap_ClosesMapOnBatchUpdateFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed: %v", err)
	}

	template, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      unix.BPF_F_NO_PREALLOC,
		MaxEntries: 4,
		KeySize:    20,
		ValueSize:  8,
	})
	if err != nil {
		t.Skipf("creating template LPM map requires BPF privileges: %v", err)
	}
	defer func() { _ = template.Close() }()

	objs := &bpfObjects{}
	objs.UnusedLpmType = template

	before, err := countOpenFDs()
	if err != nil {
		t.Fatalf("countOpenFDs before: %v", err)
	}

	_, err = objs.newLpmMap([]_bpfLpmKey{{PrefixLen: 96}}, []uint32{1})
	if err == nil {
		t.Fatal("expected newLpmMap to fail when value size mismatches the template map")
	}

	after, err := countOpenFDs()
	if err != nil {
		t.Fatalf("countOpenFDs after: %v", err)
	}
	if after != before {
		t.Fatalf("newLpmMap leaked a map FD on error: before=%d after=%d", before, after)
	}
}

func countOpenFDs() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
