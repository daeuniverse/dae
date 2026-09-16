/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

// The two steady-state datapath reports demoted here describe by-design
// behaviour, not anomalies: SynRebindRerouted is the expected, counted
// outcome of a staged reload handoff (a live flow's next pure SYN adopts
// the current routing epoch), and the passthrough summary counts packets
// that every pre-existing established flow produces after a restart for
// as long as those flows live. Under the grading rule introduced by the
// log-grading change (per-flow or per-connection decisions belong on
// debug; warn is for anomalies and rarity) both belong on debug: they
// stay fully inspectable with --log-level debug while the default level
// stops paging the operator roughly once a minute for a healthy system.
// The genuine anomaly sites (SynRebindRejected, RedirectRebindRejected,
// RedirectUpdateFailed) keep their warning level; the contract tests
// below pin both sides of that line.
func reroutedEvent() daeEvent {
	// The ringbuf record stores the address words and ports in native
	// (host) byte order; netIPString/netPortString re-encode them with the
	// same ABI before formatting, so the literals here are byte-swapped
	// views of 192.168.4.10:47712 > 149.154.167.220:443 on little-endian.
	return daeEvent{
		Type:     daeEventSynRebindRerouted,
		Pid:      44905,
		Outbound: 0,
		L4proto:  unix.IPPROTO_TCP,
		Sip:      fourWordIP(net.ParseIP("192.168.4.10")),
		Dip:      fourWordIP(net.ParseIP("149.154.167.220")),
		Sport:    swap16(47712),
		Dport:    swap16(443),
	}
}

func swap16(v uint16) uint16 { return v<<8 | v>>8 }

func fourWordIP(ip net.IP) [4]uint32 {
	// netIPString writes each word natively into 16 bytes and hands the
	// buffer to net.IP, so a dotted quad needs the ::ffff: prefix bytes:
	// words {0, 0, 0xFFFF0000, <addr LE-serialized into the low word>}.
	ip4 := ip.To4()
	var last uint32
	for i := range 4 {
		last |= uint32(ip4[i]) << (8 * i)
	}
	return [4]uint32{0, 0, 0xFFFF0000, last}
}

func TestSynRebindReroutedLogsAtDebug(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	plane := &ControlPlane{log: logger}

	ev := reroutedEvent()
	reportDatapathFlowEvent(plane, &ev, "pure SYN moved a live flow that outlived a rules change onto the current routing epoch")

	entry := hook.LastEntry()
	if entry == nil {
		t.Fatal("the re-route report produced no log line")
	}
	if entry.Level != logrus.DebugLevel {
		t.Fatalf("re-route level = %v, want debug (steady-state reload handoff)", entry.Level)
	}
	if want := "datapath anomaly:"; !strings.Contains(entry.Message, want) {
		t.Fatalf("message %q does not carry the %q prefix", entry.Message, want)
	}
	for _, want := range []string{"type=9", "192.168.4.10:47712", "149.154.167.220:443"} {
		if !strings.Contains(entry.Message, want) {
			t.Fatalf("message %q does not carry %q", entry.Message, want)
		}
	}
}

func TestGenuineAnomaliesStayAtWarn(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.InfoLevel)
	plane := &ControlPlane{log: logger}

	ev := reroutedEvent()
	ev.Type = daeEventSynRebindRejected
	reportDatapathAnomaly(plane, &ev, "pure SYN refused rewrite of a live flow's routing metadata")

	entry := hook.LastEntry()
	if entry == nil {
		t.Fatal("the anomaly report produced no log line")
	}
	if entry.Level != logrus.WarnLevel {
		t.Fatalf("anomaly level = %v, want warn (genuine anomaly must stay visible)", entry.Level)
	}
}

func TestDatapathPassthroughSummaryLogsAtDebug(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	plane := &ControlPlane{log: logger}

	// Prime, then cross both the pacing window and the moved counter, the
	// way the existing summary tests do.
	base := time.Unix(1_700_000_000, 0)
	plane.reportDatapathPassthroughSummary(base, bpfStatsSnapshot{StatelessTCPPassthrough: 100})
	plane.reportDatapathPassthroughSummary(base.Add(datapathPassthroughReportInterval), bpfStatsSnapshot{StatelessTCPPassthrough: 900})

	entry := hook.LastEntry()
	if entry == nil {
		t.Fatal("the passthrough summary produced no log line")
	}
	if entry.Level != logrus.DebugLevel {
		t.Fatalf("passthrough summary level = %v, want debug (by-design steady state)", entry.Level)
	}
}
