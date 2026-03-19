//go:build linux && dae_bpf_tests
// +build linux,dae_bpf_tests

package control

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLoadMainBPFObjects(t *testing.T) {
	var obj bpfObjects
	pinPath := "/sys/fs/bpf/dae"
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		t.Fatalf("mkdir pin path: %v", err)
	}

	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	}

	constants := map[string]interface{}{
		"PARAM": struct {
			tproxyPort      uint32
			controlPlanePid uint32
			dae0Ifindex     uint32
			daeNetnsId      uint32
			dae0peerMac     [6]byte
			useRedirectPeer uint8
			padding         uint8
		}{},
	}

	if err := loadBpfObjectsWithConstants(&obj, opts, constants); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load main bpf objects: verifier:\n%+v", ve)
		}
		t.Fatalf("load main bpf objects: %+v", err)
	}
	defer obj.Close()
}
