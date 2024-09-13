/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
)

//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" "$BPF_STRIP_FLAG" -cflags "$BPF_CFLAGS" -target "$BPF_TRACE_TARGET" -type event bpf kern/trace.c -- -I./headers

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func StartTrace(ctx context.Context, ipVersion int, l4ProtoNo uint16, port int, dropOnly bool, outputFile string) (err error) {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}
	if requirement := consts.HelperBpfGetFuncIpVersionFeatureVersion; kernelVersion.Less(requirement) {
		return fmt.Errorf("your kernel version %v does not support bpf_get_func_ip; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	objs, err := rewriteAndLoadBpf(ipVersion, l4ProtoNo, port)
	if err != nil {
		return
	}
	defer objs.Close()

	targets, kfreeSkbReasons, err := searchAvailableTargets()
	if err != nil {
		return
	}

	links, err := attachBpfToTargets(objs, targets)
	if err != nil {
		return
	}
	defer func() {
		i := 0
		fmt.Printf("\n")
		for _, link := range links {
			i++
			fmt.Printf("detaching kprobes: %04d/%04d\r", i, len(links))
			link.Close()
		}
		fmt.Printf("\n")
	}()

	fmt.Printf("\nstart tracing\n")
	if err = handleEvents(ctx, objs, outputFile, kfreeSkbReasons, dropOnly); err != nil {
		return
	}
	return
}

func rewriteAndLoadBpf(ipVersion int, l4ProtoNo uint16, port int) (_ *bpfObjects, err error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF: %+v\n", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"tracing_cfg": struct {
			port      uint16
			l4Proto   uint16
			ipVersion uint8
			pad       uint8
		}{
			port:      Htons(uint16(port)),
			l4Proto:   uint16(l4ProtoNo),
			ipVersion: uint8(ipVersion),
			pad:       0,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to rewrite constants: %+v\n", err)
	}
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return nil, fmt.Errorf("failed to load BPF: %+v\n%s", err, verifierLog)
	}

	return &objs, nil
}

func searchAvailableTargets() (targets map[string]int, kfreeSkbReasons map[uint64]string, err error) {
	targets = map[string]int{}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	if kfreeSkbReasons, err = getKFreeSKBReasons(btfSpec); err != nil {
		return
	}

	iter := btfSpec.Iterate()
	for iter.Next() {
		typ := iter.Type
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := string(fn.Name)

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" && i <= 5 {
						name := fnName
						targets[name] = i
						continue
					}
				}
			}
			i += 1
		}
	}

	return targets, kfreeSkbReasons, nil
}

func getKFreeSKBReasons(spec *btf.Spec) (map[uint64]string, error) {
	if _, err := spec.AnyTypeByName("kfree_skb_reason"); err != nil {
		// Kernel is too old to have kfree_skb_reason
		return nil, nil
	}

	var dropReasonsEnum *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &dropReasonsEnum); err != nil {
		return nil, fmt.Errorf("failed to find 'skb_drop_reason' enum: %v", err)
	}

	ret := map[uint64]string{}
	for _, val := range dropReasonsEnum.Values {
		ret[uint64(val.Value)] = val.Name

	}

	return ret, nil
}

func attachBpfToTargets(objs *bpfObjects, targets map[string]int) (links []link.Link, err error) {
	kp, err := link.Kprobe("kfree_skbmem", objs.KprobeSkbLifetimeTermination, nil)
	if err != nil {
		logrus.Warnf("failed to attach kprobe to kfree_skbmem: %+v\n", err)
	}

	i := 0
	for fn, pos := range targets {
		i++
		fmt.Printf("attaching kprobes: %04d/%04d\r", i, len(targets))
		var kp link.Link
		switch pos {
		case 1:
			kp, err = link.Kprobe(fn, objs.KprobeSkb1, nil)
		case 2:
			kp, err = link.Kprobe(fn, objs.KprobeSkb2, nil)
		case 3:
			kp, err = link.Kprobe(fn, objs.KprobeSkb3, nil)
		case 4:
			kp, err = link.Kprobe(fn, objs.KprobeSkb4, nil)
		case 5:
			kp, err = link.Kprobe(fn, objs.KprobeSkb5, nil)
		}
		if err != nil {
			logrus.Debugf("failed to attach kprobe to %s: %+v\n", fn, err)
			continue
		}
		links = append(links, kp)
	}
	if len(links) == 0 {
		err = fmt.Errorf("failed to attach kprobes to any target")
	}
	links = append(links, kp)
	return links, nil
}

func handleEvents(ctx context.Context, objs *bpfObjects, outputFile string, kfreeSkbReasons map[uint64]string, dropOnly bool) (err error) {
	writer, err := os.Create(outputFile)
	if err != nil {
		return
	}

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %+v\n", err)
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	type bpfEvent struct {
		Pc          uint64
		Skb         uint64
		SecondParam uint64
		Mark        uint32
		Netns       uint32
		Ifindex     uint32
		Pid         uint32
		Ifname      [16]uint8
		Pname       [32]uint8
		Saddr       [16]byte
		Daddr       [16]byte
		Sport       uint16
		Dport       uint16
		L3Proto     uint16
		L4Proto     uint8
		TcpFlags    uint8
		PayloadLen  uint16
	}

	var	skb2events map[uint64][]bpfEvent
	skb2events = make(map[uint64][]bpfEvent)
	// a map to save slices of bpfEvent of the Skb
	var skb2sysNames map[uint64][]string
	skb2sysNames = make(map[uint64][]string)
	// a map to save slices of function name called with the Skb
	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			logrus.Debugf("failed to read ringbuf: %+v", err)
			continue
		}

		var event bpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			logrus.Debugf("failed to parse ringbuf event: %+v", err)
			continue
		}
		if skb2events[event.Skb]==nil {
		    skb2events[event.Skb] = []bpfEvent{}
		}
		skb2events[event.Skb] = append(skb2events[event.Skb],event)


		sym := NearestSymbol(event.Pc);
		if skb2sysNames[event.Skb]==nil {
			skb2sysNames[event.Skb] = []string{}
		}
		skb2sysNames[event.Skb] = append(skb2sysNames[event.Skb],sym.Name)
		switch sym.Name {
			case "__kfree_skb","kfree_skbmem":
				// most skb end in the call of kfree_skbmem
			    if !dropOnly || slices.Contains(skb2sysNames[event.Skb],"kfree_skb_reason") {
					// track dropOnly with drop reason or all skb
					for _,skb_ev := range skb2events[event.Skb] {
						fmt.Fprintf(writer, "%x mark=%x netns=%010d if=%d(%s) proc=%d(%s) ", skb_ev.Skb, skb_ev.Mark, skb_ev.Netns, skb_ev.Ifindex, TrimNull(string(skb_ev.Ifname[:])), skb_ev.Pid, TrimNull(string(skb_ev.Pname[:])))
						if event.L3Proto == syscall.ETH_P_IP {
							fmt.Fprintf(writer, "%s:%d > %s:%d ", net.IP(skb_ev.Saddr[:4]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:4]).String(), Ntohs(skb_ev.Dport))
						} else {
							fmt.Fprintf(writer, "[%s]:%d > [%s]:%d ", net.IP(skb_ev.Saddr[:]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:]).String(), Ntohs(skb_ev.Dport))
						}
						if event.L4Proto == syscall.IPPROTO_TCP {
							fmt.Fprintf(writer, "tcp_flags=%s ", TcpFlags(skb_ev.TcpFlags))
						}
						fmt.Fprintf(writer, "payload_len=%d ", event.PayloadLen)
						sym := NearestSymbol(skb_ev.Pc)
						fmt.Fprintf(writer, "%s", sym.Name)
						if sym.Name == "kfree_skb_reason" {
							fmt.Fprintf(writer, "(%s)", kfreeSkbReasons[skb_ev.SecondParam])
						}
						fmt.Fprintf(writer, "\n")
					}
				delete(skb2events, event.Skb)
			    }
		}
	}
}
