/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

func accountTestBTF(nargs int) *btf.Func {
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	params := []btf.FuncParam{
		{Name: "sk", Type: &btf.Pointer{Target: &btf.Struct{Name: "sock"}}},
		{Name: "skb", Type: &btf.Pointer{Target: &btf.Struct{Name: "sk_buff"}}},
		{Name: "offset", Type: integer},
		{Name: "len", Type: integer},
	}
	if nargs == 6 {
		params = append(params, btf.FuncParam{Name: "sendmsg", Type: &btf.Pointer{Target: &btf.FuncProto{}}}, btf.FuncParam{Name: "flags", Type: integer})
	}
	return &btf.Func{Type: &btf.FuncProto{Return: integer, Params: params}}
}

func TestTCPOffloadAccountSelector(t *testing.T) {
	const outer = "0000000000000000 T skb_send_sock\n"
	const inner = "0000000000000000 t __skb_send_sock.llvm.123456789\n"
	for _, tc := range []struct {
		name    string
		symbols string
		arch    string
		btfErr  bool
		mutate  func(*btf.Func)
		want    string
		inner   bool
		wantErr bool
	}{
		{name: "LTO inner suffix", symbols: outer + inner, want: "__skb_send_sock.llvm.123456789", inner: true},
		{name: "inner without wrapper", symbols: inner, want: "__skb_send_sock.llvm.123456789", inner: true},
		{name: "non LTO inner", symbols: outer + "0 t __skb_send_sock\n", want: "__skb_send_sock", inner: true},
		{name: "6.6 and 6.12 five argument inner", symbols: outer + "0 t __skb_send_sock\n", mutate: func(fn *btf.Func) {
			fn.Type.(*btf.FuncProto).Params = fn.Type.(*btf.FuncProto).Params[:5]
		}, want: "__skb_send_sock", inner: true},
		{name: "ordinary wrapper", symbols: outer, want: tcpRelayOffloadAccountTarget},
		{name: "non x86 wrapper", symbols: outer, arch: "arm64", want: tcpRelayOffloadAccountTarget},
		{name: "module inner ignored", symbols: outer + "0 t __skb_send_sock.llvm.1 [module]\n", want: tcpRelayOffloadAccountTarget},
		{name: "data symbol ignored", symbols: outer + "0 d __skb_send_sock\n", want: tcpRelayOffloadAccountTarget},
		{name: "missing symbols", wantErr: true},
		{name: "missing BTF", symbols: outer + inner, btfErr: true, wantErr: true},
		{name: "wrapper missing BTF", symbols: outer, btfErr: true, wantErr: true},
		{name: "unsupported arch inner", symbols: outer + inner, arch: "arm64", wantErr: true},
		{name: "multiple clones", symbols: outer + inner + "0 t __skb_send_sock.llvm.2\n", wantErr: true},
		{name: "duplicate exact inner", symbols: "0 t __skb_send_sock\n0 t __skb_send_sock\n", wantErr: true},
		{name: "unknown clone ABI", symbols: outer + "0 t __skb_send_sock.isra.0\n", wantErr: true},
		{name: "empty LLVM suffix", symbols: outer + "0 t __skb_send_sock.llvm.\n", wantErr: true},
		{name: "invalid LLVM suffix", symbols: outer + "0 t __skb_send_sock.llvm.123x\n", wantErr: true},
		{name: "wrong arity", symbols: outer + inner, mutate: func(fn *btf.Func) { fn.Type.(*btf.FuncProto).Params = fn.Type.(*btf.FuncProto).Params[:4] }, wantErr: true},
		{name: "swapped pointer ABI", symbols: outer + inner, mutate: func(fn *btf.Func) { p := fn.Type.(*btf.FuncProto); p.Params[0], p.Params[1] = p.Params[1], p.Params[0] }, wantErr: true},
		{name: "wrong length width", symbols: outer + inner, mutate: func(fn *btf.Func) { fn.Type.(*btf.FuncProto).Params[3].Type = &btf.Int{Size: 8, Encoding: btf.Signed} }, wantErr: true},
		{name: "unsigned offset", symbols: outer + inner, mutate: func(fn *btf.Func) {
			fn.Type.(*btf.FuncProto).Params[2].Type = &btf.Int{Size: 4, Encoding: btf.Unsigned}
		}, wantErr: true},
		{name: "non function BTF", symbols: outer + inner, mutate: func(fn *btf.Func) { fn.Type = &btf.Int{} }, wantErr: true},
		{name: "qualified typedef ABI", symbols: outer + inner, mutate: func(fn *btf.Func) {
			p := fn.Type.(*btf.FuncProto)
			p.Params[1].Type = &btf.Typedef{Name: "skb_ptr", Type: &btf.Const{Type: p.Params[1].Type}}
		}, want: "__skb_send_sock.llvm.123456789", inner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := tc.arch
			if arch == "" {
				arch = "amd64"
			}
			hook, err := selectTCPOffloadAccountHook(strings.NewReader(tc.symbols), func(name string) (*btf.Func, error) {
				if tc.btfErr {
					return nil, stderrors.New("BTF unavailable")
				}
				nargs := 4
				if name == tcpRelayOffloadInnerTarget {
					nargs = 6
				}
				fn := accountTestBTF(nargs)
				if tc.mutate != nil {
					tc.mutate(fn)
				}
				return fn, nil
			}, arch)
			if (err != nil) != tc.wantErr {
				t.Fatalf("hook=%+v err=%v, wantErr=%v", hook, err, tc.wantErr)
			}
			if err == nil && (hook.target != tc.want || hook.kprobeOnly != tc.inner) {
				t.Fatalf("hook=%+v, want target=%s inner=%v", hook, tc.want, tc.inner)
			}
		})
	}
}

func TestTCPOffloadAccountAttachSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inner      bool
		arch       string
		fentryFail bool
		kprobeFail bool
		wantFentry int
		wantKprobe int
		wantErr    bool
	}{
		{name: "wrapper fentry", arch: "amd64", wantFentry: 1},
		{name: "router kprobe fallback", arch: "amd64", fentryFail: true, wantFentry: 1, wantKprobe: 1},
		{name: "inner never attaches dead wrapper", inner: true, arch: "amd64", wantKprobe: 1},
		{name: "inner failure never falls back to wrapper", inner: true, arch: "amd64", kprobeFail: true, wantKprobe: 1, wantErr: true},
		{name: "no x86 fallback on arm64", arch: "arm64", fentryFail: true, wantFentry: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := tcpOffloadAccountHook{target: tcpRelayOffloadAccountTarget, kprobeOnly: tc.inner}
			if tc.inner {
				hook.target = "__skb_send_sock.llvm.987"
			}
			var fentryCalls, kprobeCalls int
			_, description, err := attachSelectedTCPOffloadAccount(hook, tc.arch, func() (link.Link, error) {
				fentryCalls++
				if tc.fentryFail {
					return nil, stderrors.New("no ftrace entry")
				}
				return nil, nil
			}, func(target string) (link.Link, error) {
				kprobeCalls++
				if target != hook.target {
					t.Fatalf("kprobe target=%s, want %s", target, hook.target)
				}
				if tc.kprobeFail {
					return nil, stderrors.New("kprobe rejected")
				}
				return nil, nil
			})
			if (err != nil) != tc.wantErr || fentryCalls != tc.wantFentry || kprobeCalls != tc.wantKprobe {
				t.Fatalf("err=%v fentry=%d kprobe=%d", err, fentryCalls, kprobeCalls)
			}
			if err == nil && !strings.HasSuffix(description, "/"+hook.target) {
				t.Fatalf("wrong hook description %q", description)
			}
		})
	}
}
