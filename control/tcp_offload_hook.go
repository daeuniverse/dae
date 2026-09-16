/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

const tcpRelayOffloadInnerTarget = "__skb_send_sock"

type tcpOffloadAccountHook struct {
	target     string
	kprobeOnly bool
}

// selectTCPOffloadAccountHook uses only kernel metadata, never traffic probes.
// LTO can bypass skb_send_sock while retaining its attachable wrapper. Prefer
// the shared inner implementation when it has an addressable, verified ABI.
//
// Availability tradeoff: when an inner symbol exists, the hook stays
// kprobe-only and never falls back to fentry on the possibly-bypassed outer
// wrapper. Attaching to a bypassed wrapper silently under-counts sent bytes,
// which inflates the backlog estimate and can falsely engage the pause fuse —
// strictly worse than the explicit disable taken here. The cost is that
// non-amd64 kernels, or kernels built without CONFIG_KPROBES, that expose an
// inner symbol disable TCP offload instead of gambling on the outer wrapper.
func selectTCPOffloadAccountHook(symbols io.Reader, lookup func(string) (*btf.Func, error), goarch string) (tcpOffloadAccountHook, error) {
	var inner []string
	outer := false
	scanner := bufio.NewScanner(symbols)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Module symbols cannot implement the built-in sockmap send path.
		if len(fields) != 3 || (fields[1] != "t" && fields[1] != "T") {
			continue
		}
		name := fields[2]
		if name == tcpRelayOffloadAccountTarget {
			outer = true
		}
		if name == tcpRelayOffloadInnerTarget || strings.HasPrefix(name, tcpRelayOffloadInnerTarget+".") {
			inner = append(inner, name)
		}
	}
	if err := scanner.Err(); err != nil {
		return tcpOffloadAccountHook{}, fmt.Errorf("read accounting symbols: %w", err)
	}
	hook := tcpOffloadAccountHook{target: tcpRelayOffloadAccountTarget}
	btfName, nargs := hook.target, 4
	if len(inner) != 0 {
		if len(inner) != 1 || !tcpOffloadInnerSymbolSupported(inner[0]) {
			return tcpOffloadAccountHook{}, fmt.Errorf("ambiguous or unsupported inner accounting symbols: %v", inner)
		}
		if !tcpOffloadKprobeFallbackSupported(goarch) {
			return tcpOffloadAccountHook{}, fmt.Errorf("inner accounting requires a supported kprobe ABI, GOARCH=%s", goarch)
		}
		hook = tcpOffloadAccountHook{target: inner[0], kprobeOnly: true}
		btfName, nargs = tcpRelayOffloadInnerTarget, 6
	} else if !outer {
		return tcpOffloadAccountHook{}, fmt.Errorf("no addressable TCP offload accounting symbol")
	}
	fn, err := lookup(btfName)
	if err != nil {
		return tcpOffloadAccountHook{}, fmt.Errorf("accounting BTF %s: %w", btfName, err)
	}
	if !tcpOffloadAccountABICompatible(fn, nargs) {
		return tcpOffloadAccountHook{}, fmt.Errorf("incompatible accounting BTF ABI for %s", btfName)
	}
	return hook, nil
}

func tcpOffloadInnerSymbolSupported(name string) bool {
	if name == tcpRelayOffloadInnerTarget {
		return true
	}
	suffix, ok := strings.CutPrefix(name, tcpRelayOffloadInnerTarget+".llvm.")
	if !ok || suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func tcpOffloadAccountABICompatible(fn *btf.Func, nargs int) bool {
	if fn == nil {
		return false
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return false
	}
	// Linux 6.6/6.12 pass sendmsg as the fifth inner argument; newer
	// kernels add flags as the sixth. Both preserve the consumed prefix.
	if len(proto.Params) != nargs && (nargs != 6 || len(proto.Params) != 5) {
		return false
	}
	isInt := func(typ btf.Type) bool {
		i, ok := btf.UnderlyingType(typ).(*btf.Int)
		return ok && i.Size == 4 && i.Encoding == btf.Signed
	}
	for i, name := range []string{"sock", "sk_buff"} {
		ptr, ok := btf.UnderlyingType(proto.Params[i].Type).(*btf.Pointer)
		if !ok {
			return false
		}
		st, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
		if !ok || st.Name != name {
			return false
		}
	}
	// The existing programs read only the first four arguments. Trailing
	// inner arguments are not consumed by the x86 kprobe program.
	return isInt(proto.Return) && isInt(proto.Params[2].Type) && isInt(proto.Params[3].Type)
}

func resolveTCPOffloadAccountHook() (tcpOffloadAccountHook, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return tcpOffloadAccountHook{}, fmt.Errorf("load accounting BTF: %w", err)
	}
	symbols, err := os.Open("/proc/kallsyms")
	if err != nil {
		return tcpOffloadAccountHook{}, fmt.Errorf("open accounting symbols: %w", err)
	}
	defer func() { _ = symbols.Close() }()
	return selectTCPOffloadAccountHook(symbols, func(name string) (*btf.Func, error) {
		var fn *btf.Func
		err := spec.TypeByName(name, &fn)
		return fn, err
	}, runtime.GOARCH)
}

// attachTCPOffloadAccount is shared by production and the private-map E2E.
// It must run inside the registry's attach callback, so reload reuses links.
func attachTCPOffloadAccount(fentry, kprobe *ebpf.Program) (link.Link, string, error) {
	hook, err := resolveTCPOffloadAccountHook()
	if err != nil {
		return nil, "", err
	}
	return attachSelectedTCPOffloadAccount(hook, runtime.GOARCH, func() (link.Link, error) {
		if fentry == nil {
			return nil, fmt.Errorf("fentry accounting program unavailable")
		}
		return link.AttachTracing(link.TracingOptions{Program: fentry, AttachType: ebpf.AttachTraceFEntry})
	}, func(target string) (link.Link, error) {
		if kprobe == nil {
			return nil, fmt.Errorf("kprobe accounting program unavailable")
		}
		return link.Kprobe(target, kprobe, nil)
	})
}

func attachSelectedTCPOffloadAccount(hook tcpOffloadAccountHook, goarch string, fentry func() (link.Link, error), kprobe func(string) (link.Link, error)) (link.Link, string, error) {
	var fentryErr error
	if !hook.kprobeOnly {
		var l link.Link
		l, fentryErr = fentry()
		if fentryErr == nil {
			return l, "fentry/" + hook.target, nil
		}
	}
	if !tcpOffloadKprobeFallbackSupported(goarch) {
		return nil, "", fmt.Errorf("accounting kprobe ABI unavailable on %s (fentry: %v)", goarch, fentryErr)
	}
	l, err := kprobe(hook.target)
	if err != nil {
		return nil, "", fmt.Errorf("attach accounting kprobe/%s (fentry: %v): %w", hook.target, fentryErr, err)
	}
	return l, "kprobe/" + hook.target, nil
}
