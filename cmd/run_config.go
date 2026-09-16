/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func monotonicNowNano() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

// detectCgroupMemLimit returns the smallest finite memory.max applying to the
// current cgroup. Parent ceilings still constrain children, so the complete
// path is inspected instead of stopping at the first value.
func detectCgroupMemLimit() int64 {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		// Not in cgroup v2 or can't read; try root-level (container case).
		return readCgroupMemoryCeiling("/sys/fs/cgroup")
	}
	return detectCgroupMemLimitFrom(data, "/sys/fs/cgroup")
}

func detectCgroupMemLimitFrom(data []byte, root string) int64 {
	var limit int64
	for line := range strings.SplitSeq(string(data), "\n") {
		// cgroup v2 unified hierarchy format: "0::/path"
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		cgPath := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		for {
			limit = minPositive(limit, readCgroupMemoryCeiling(filepath.Join(root, cgPath)))
			if cgPath == "/" || cgPath == "." || cgPath == "" {
				break
			}
			idx := strings.LastIndexByte(cgPath, '/')
			if idx <= 0 {
				cgPath = "/"
			} else {
				cgPath = cgPath[:idx]
			}
		}
		return limit
	}
	return readCgroupMemoryCeiling(root)
}

// readCgroupMemoryCeiling reads memory.max from a cgroup v2 directory.
// Returns 0 if the file is missing, set to "max", or unparseable.
//
// memory.high is deliberately not consulted: it throttles reclaim rather than
// capping the cgroup, so a process is allowed to sit above it. Feeding it to
// SetMemoryLimit turns a soft systemd hint into a hard Go heap ceiling.
func readCgroupMemoryCeiling(dir string) int64 {
	return readCgroupMemoryValue(dir, "memory.max")
}

func readCgroupMemoryValue(dir, name string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func minPositive(values ...int64) int64 {
	var minimum int64
	for _, value := range values {
		if value > 0 && (minimum == 0 || value < minimum) {
			minimum = value
		}
	}
	return minimum
}

func newHTTPClientForDialer(d netproxy.Dialer, timeout time.Duration, soMark uint32, mptcp bool) http.Client {
	soMark = common.EffectiveSoMarkFromDae(soMark)
	return http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := d.DialContext(ctx, common.MagicNetwork("tcp", soMark, mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
		},
		Timeout: timeout,
	}
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func emptyConfig() (conf *config.Config, err error) {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		return nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, err
	}
	return conf, nil
}
