/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type Symbol struct {
	Type string
	Name string
	Addr uint64
}

var kallsyms []Symbol
var kallsymsByName map[string]Symbol = make(map[string]Symbol)
var kallsymsByAddr map[uint64]Symbol = make(map[uint64]Symbol)

func init() {
	readKallsyms()
}

func readKallsyms() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		logrus.Fatalf("failed to open /proc/kallsyms: %v", err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		typ, name := parts[1], parts[2]
		kallsyms = append(kallsyms, Symbol{typ, name, addr})
		kallsymsByName[name] = Symbol{typ, name, addr}
		kallsymsByAddr[addr] = Symbol{typ, name, addr}
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func NearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	if idx == len(kallsyms) {
		return kallsyms[idx-1]
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx]
	}
	if idx == 0 {
		return kallsyms[0]
	}
	return kallsyms[idx-1]
}
