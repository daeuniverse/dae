//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTCPOffloadHeaderContract replays the production C helpers without BPF
// privileges. Big-endian scalar ABI inputs follow convert_skb_access in Linux;
// actual big-endian kernel execution remains a separate matrix requirement.
func TestTCPOffloadHeaderContract(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("C source replay requires clang")
	}
	for _, endian := range []string{"little", "big"} {
		t.Run(endian, func(t *testing.T) {
			executable := filepath.Join(t.TempDir(), "offload-headers")
			args := []string{"-O2", "-Wall", "-Werror", "kern/tests/tcp_offload_header_test.c", "-o", executable}
			if endian == "big" {
				args = append(args, "-DTEST_BIG_ENDIAN")
			}
			if output, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile helper replay: %v\n%s", err, output)
			}
			t.Run("ABI", func(t *testing.T) {
				if output, err := exec.Command(executable, "abi").CombinedOutput(); err != nil {
					t.Fatalf("remote_port replay: %v\n%s", err, output)
				}
			})
			if endian == "little" {
				t.Run("Headers", func(t *testing.T) {
					if output, err := exec.Command(executable, "headers").CombinedOutput(); err != nil {
						t.Fatalf("skb header replay: %v\n%s", err, output)
					}
				})
			}
		})
	}
}

func TestTCPOffloadUsesHeaderHelpers(t *testing.T) {
	source, err := os.ReadFile("kern/tproxy.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{
		"peer_key.sport = tcp_offload_remote_port(skb->remote_port)",
		"tcp_offload_skb_key(skb, &key)",
	} {
		if !strings.Contains(string(source), call) {
			t.Errorf("production datapath no longer uses the replayed helper: %s", call)
		}
	}
}
