//go:build linux && dae_bpf_tests
// +build linux,dae_bpf_tests

package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func loadBpfObjectsWithConstants(obj interface{}, opts *ebpf.CollectionOptions, constants map[string]interface{}) error {
	return loadBpfObjectsWithConstantsAndCustomizer(obj, opts, constants, nil)
}

func TestLoadMainBPFObjects(t *testing.T) {
	var obj bpfObjects
	opts := &ebpf.CollectionOptions{
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
			paddingAfterMac [2]uint8
			useRedirectPeer uint8
			padding1        uint8
			padding2        uint16
			daeSocketMark   uint32
		}{},
	}

	if err := loadBpfObjectsWithConstantsAndCustomizer(&obj, opts, constants, disableAllPinnedMapsForTests); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load main bpf objects: verifier:\n%+v", ve)
		}
		t.Fatalf("load main bpf objects: %+v", err)
	}
	defer func() { _ = obj.Close() }()
}
