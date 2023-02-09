/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/pkg/ebpf_internal"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

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

func AssignBpfObjects(to *bpfObjects, from interface{}) {
	vTo := reflect.Indirect(reflect.ValueOf(to))
	vFrom := reflect.Indirect(reflect.ValueOf(from))
	tFrom := vFrom.Type()
	// programs
	for i := 0; i < vFrom.NumField(); i++ {
		fieldFrom := vFrom.Field(i)
		structFieldFrom := tFrom.Field(i)
		if structFieldFrom.Type != reflect.TypeOf(&ebpf.Program{}) {
			continue
		}
		fieldTo := vTo.FieldByName(structFieldFrom.Name)
		fieldTo.Set(fieldFrom)
	}

	// bpfMaps
	vFrom = vFrom.FieldByName("bpfMaps")
	tFrom = vFrom.Type()
	for i := 0; i < vFrom.NumField(); i++ {
		fieldFrom := vFrom.Field(i)
		structFieldFrom := tFrom.Field(i)
		fieldTo := vTo.FieldByName(structFieldFrom.Name)
		fieldTo.Set(fieldFrom)
	}
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
	PinPath           string
	CollectionOptions *ebpf.CollectionOptions
	BindLan           bool
	BindWan           bool
}

func selectivelyLoadBpfObjects(
	log *logrus.Logger,
	bpf *bpfObjects,
	opts *loadBpfOptions,
) (err error) {
	// Trick. Replace the beams with rotten timbers to reduce the loading.
	var obj interface{} = bpf // Bind to both LAN and WAN.
	if opts.BindLan && !opts.BindWan {
		// Only bind LAN.
		obj = &bpfObjectsLan{}
	} else if !opts.BindLan && opts.BindWan {
		// Only bind to WAN.
		// Trick. Replace the beams with rotten timbers.
		obj = &bpfObjectsWan{}
	}
retryLoadBpf:
	if err = loadBpfObjects(obj, opts.CollectionOptions); err != nil {
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
			err = fmt.Errorf("%w: maybe installing the linux-headers package will solve it", err)
		}
		return err
	}
	if _, ok := obj.(*bpfObjects); !ok {
		// Reverse takeover.
		AssignBpfObjects(bpf, obj)
	}
	return nil
}
