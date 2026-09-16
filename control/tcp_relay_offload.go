package control

import (
	"os"
)

// tcpRelayOffloadPrograms and tcpRelayOffloadMaps are the BPF programs and maps
// that belong exclusively to the opt-in TCP relay eBPF offload feature. They are
// referenced only by tcp_offload_redirect and tcp_offload_sent_account(_kprobe);
// no always-on tproxy_* datapath program touches them.
//
// These programs are loaded in a separate, fault-tolerant pass (see
// loadOffloadBpfObjects): the mandatory LoadAndAssign of the datapath deliberately
// does NOT bind them, so a trimmed router kernel that cannot load a particular
// offload program (e.g. the fentry/skb_send_sock hook returning EINVAL on
// OpenWrt) cannot take down the whole datapath at start. The offload feature only
// activates if all of these programs and maps load successfully.
var tcpRelayOffloadPrograms = []string{
	"tcp_offload_redirect",
	"tcp_offload_sent_account",
	"tcp_offload_sent_account_kprobe",
}

func tcpRelayOffloadProgramsForArch(goarch string) []string {
	if tcpOffloadKprobeFallbackSupported(goarch) {
		return tcpRelayOffloadPrograms
	}
	programs := make([]string, 0, len(tcpRelayOffloadPrograms)-1)
	for _, name := range tcpRelayOffloadPrograms {
		if name != "tcp_offload_sent_account_kprobe" {
			programs = append(programs, name)
		}
	}
	return programs
}

var tcpRelayOffloadMaps = []string{
	"fast_sock",
	"tcp_offload_pause",
	"tcp_offload_sent",
}

// tcpRelayOffloadEnabled reports whether the opt-in TCP relay eBPF offload
// feature is enabled. It mirrors the gate in controlPlaneCore.setupTCPRelayOffload
// so the load-time behavior and the attach-time gate stay consistent: the feature
// is on only when it is not forcibly disabled AND the user opted in via
// DAE_ALLOW_TCP_SOCKMAP=1.
func tcpRelayOffloadEnabled() bool {
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		return false
	}
	return os.Getenv("DAE_ALLOW_TCP_SOCKMAP") == "1"
}
