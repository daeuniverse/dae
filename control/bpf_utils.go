/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
)

type _bpfTuples struct {
	Sip     [4]uint32
	Dip     [4]uint32
	Sport   uint16
	Dport   uint16
	L4proto uint8
	_       [3]byte
}

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

type _bpfPortRange struct {
	PortStart uint16
	PortEnd   uint16
}

func (r _bpfPortRange) Encode() (b [16]byte) {
	binary.LittleEndian.PutUint16(b[:2], r.PortStart)
	binary.LittleEndian.PutUint16(b[2:], r.PortEnd)
	return b
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	portStart = binary.LittleEndian.Uint16(b[:2])
	portEnd = binary.LittleEndian.Uint16(b[2:])
	return portStart, portEnd
}

func (o *bpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	m, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      o.UnusedLpmType.Flags(),
		MaxEntries: o.UnusedLpmType.MaxEntries(),
		KeySize:    o.UnusedLpmType.KeySize(),
		ValueSize:  o.UnusedLpmType.ValueSize(),
	})
	if err != nil {
		return nil, err
	}
	if _, err = BpfMapBatchUpdate(m, keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return nil, err
	}
	return m, nil
}

func cidrToBpfLpmKey(prefix netip.Prefix) _bpfLpmKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	return _bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}

var (
	CheckBatchUpdateFeatureOnce sync.Once
	SimulateBatchUpdate         bool
	SimulateBatchUpdateLpmTrie  bool
)

func BpfMapBatchUpdate(m *ebpf.Map, keys interface{}, values interface{}, opts *ebpf.BatchOptions) (n int, err error) {
	CheckBatchUpdateFeatureOnce.Do(func() {
		version, e := internal.KernelVersion()
		if e != nil {
			SimulateBatchUpdate = true
			SimulateBatchUpdateLpmTrie = true
			return
		}
		if version.Less(consts.UserspaceBatchUpdateFeatureVersion) {
			SimulateBatchUpdate = true
		}
		if version.Less(consts.UserspaceBatchUpdateLpmTrieFeatureVersion) {
			SimulateBatchUpdateLpmTrie = true
		}
	})

	simulate := SimulateBatchUpdate
	if m.Type() == ebpf.LPMTrie {
		simulate = SimulateBatchUpdateLpmTrie
	}

	if !simulate {
		// Genuine BpfMapBatchUpdate
		return m.BatchUpdate(keys, values, opts)
	}

	// Simulate
	vKeys := reflect.ValueOf(keys)
	if vKeys.Kind() != reflect.Slice {
		return 0, fmt.Errorf("keys must be slice")
	}
	vVals := reflect.ValueOf(values)
	if vVals.Kind() != reflect.Slice {
		return 0, fmt.Errorf("values must be slice")
	}
	length := vKeys.Len()
	if vVals.Len() != length {
		return 0, fmt.Errorf("keys and values must have same length")
	}

	for i := 0; i < length; i++ {
		vKey := vKeys.Index(i)
		vVal := vVals.Index(i)
		if err = m.Update(vKey.Interface(), vVal.Interface(), ebpf.MapUpdateFlags(opts.ElemFlags)); err != nil {
			return i, err
		}
	}
	return vKeys.Len(), nil
}

// BpfMapBatchDelete deletes keys and ignores ErrKeyNotExist.
func BpfMapBatchDelete(m *ebpf.Map, keys interface{}) (n int, err error) {
	// Simulate
	vKeys := reflect.ValueOf(keys)
	if vKeys.Kind() != reflect.Slice {
		return 0, fmt.Errorf("keys must be slice")
	}
	length := vKeys.Len()

	for i := 0; i < length; i++ {
		vKey := vKeys.Index(i)
		if err = m.Delete(vKey.Interface()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return i, err
		}
	}
	return vKeys.Len(), nil
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/examples/cgroup_skb/main.go
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func (p bpfIfParams) CheckVersionRequirement(version *internal.Version) (err error) {
	if !p.TxL4CksmIp4Offload ||
		!p.TxL4CksmIp6Offload {
		// Need calc checksum on CPU. And need BPF_F_ADJ_ROOM_NO_CSUM_RESET.
		if version.Less(consts.ChecksumFeatureVersion) {
			return fmt.Errorf("your NIC does not support checksum offload and your kernel version %v does not support related BPF features; expect >=%v; upgrade your kernel and try again", version.String(),
				consts.ChecksumFeatureVersion.String())
		}
	}
	return nil
}

type loadBpfOptions struct {
	PinPath             string
	BigEndianTproxyPort uint32
	CollectionOptions   *ebpf.CollectionOptions
}

func loadBpfObjectsWithConstants(obj interface{}, opts *ebpf.CollectionOptions, constants map[string]interface{}) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	if err := spec.RewriteConstants(constants); err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}

func fullLoadBpfObjects(
	log *logrus.Logger,
	bpf *bpfObjects,
	opts *loadBpfOptions,
) (err error) {
retryLoadBpf:
	netnsID, err := GetDaeNetns().NetnsID()
	if err != nil {
		return fmt.Errorf("failed to get netns id: %w", err)
	}
	println("netnsID", netnsID)
	constants := map[string]interface{}{
		"PARAM": struct {
			tproxyPort      uint32
			controlPlanePid uint32
			dae0Ifindex     uint32
			dae0NetnsId     uint32
			dae0peerMac     [6]byte
			padding         [2]byte
		}{
			tproxyPort:      uint32(opts.BigEndianTproxyPort),
			controlPlanePid: uint32(os.Getpid()),
			dae0Ifindex:     uint32(GetDaeNetns().Dae0().Attrs().Index),
			dae0NetnsId:     uint32(netnsID),
			dae0peerMac:     [6]byte(GetDaeNetns().Dae0Peer().Attrs().HardwareAddr),
		},
	}
	if err = loadBpfObjectsWithConstants(bpf, opts.CollectionOptions, constants); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			// Map property is incompatible. Remove the old map and try again.
			prefix := "use pinned map "
			_, after, ok := strings.Cut(err.Error(), prefix)
			if !ok {
				return fmt.Errorf("loading objects: bad format: %w", err)
			}
			mapName, _, _ := strings.Cut(after, ":")
			_ = os.Remove(filepath.Join(opts.PinPath, mapName))
			log.Infof("Incompatible new map format with existing map %v detected; removed the old one.", mapName)
			goto retryLoadBpf
		}
		// Get detailed log from ebpf.internal.(*VerifierError)
		if log.Level == logrus.FatalLevel {
			if v := reflect.Indirect(reflect.ValueOf(errors.Unwrap(errors.Unwrap(err)))); v.Kind() == reflect.Struct {
				if _log := v.FieldByName("Log"); _log.IsValid() {
					if strSlice, ok := _log.Interface().([]string); ok {
						log.Fatalln(strings.Join(strSlice, "\n"))
					}
				}
			}
		}
		if strings.Contains(err.Error(), "no BTF found for kernel version") {
			err = fmt.Errorf("%w: you should re-compile linux kernel with BTF configurations; see docs for more information", err)
		} else if strings.Contains(err.Error(), "unknown func bpf_trace_printk") {
			err = fmt.Errorf(`%w: please try to compile dae without bpf_printk"`, err)
		} else if strings.Contains(err.Error(), "unknown func bpf_probe_read") {
			err = fmt.Errorf(`%w: please re-compile linux kernel with CONFIG_BPF_EVENTS=y and CONFIG_KPROBE_EVENTS=y"`, err)
		}
		return err
	}
	return nil
}
