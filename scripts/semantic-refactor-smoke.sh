#!/usr/bin/env bash
#
# Consolidated real-BPF smoke harness for dae (replaces the former
# semantic-refactor-live-*.sh family).
#
# Subcommands:
#   lifecycle   <binary> [config] [rounds]         startup/reload/recovery, empty config
#   tcp-local   <binary> [rounds]                  WAN-hook TCP over veth (deterministic)
#   udp-local   <binary> [rounds]                  WAN-hook UDP over veth (deterministic)
#   quic-local  <binary> [rounds]                  WAN-hook QUIC datagrams over veth
#   iperf-local <binary> [duration] [udp-rate]     TCP+UDP throughput over veth
#   tcp-public  <binary> [host] [rounds]           WAN-hook HTTPS via public endpoint
#   udp-public  <binary> [resolver] [rounds]       public DNS UDP during reload
#   quic-public <binary> [target] [rounds]         public HTTP/3 during reload
#   dns         <binary> [upstream] [rounds]       DNS listener + cache path
#
# Every subcommand requires root and refuses to touch an existing dae
# deployment (dae0, daens, /sys/fs/bpf/dae). The *-local variants are fully
# deterministic (temporary veth + network namespace); the *-public variants
# depend on outbound connectivity and are meant for manual runs.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

binary=
config_file=
tmp_dir=
daemon_pid=
request_pid=
client_pid=
server_pid=
mounted_here=0
cleanup_done=0
extra_links=()
extra_namespaces=()
shutdown_timeout_seconds=${DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS:-15}

usage() {
	sed -n '3,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
	exit 2
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "this smoke test requires root" >&2
		exit 1
	fi
}

require_commands() {
	local command_name
	for command_name in "$@"; do
		if ! command -v "$command_name" >/dev/null 2>&1; then
			echo "required command is missing: $command_name" >&2
			exit 1
		fi
	done
}

require_positive_int() {
	local name=$1
	local value=$2
	if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
		echo "$name must be a positive integer" >&2
		exit 1
	fi
}

require_binary() {
	if [ ! -x "$binary" ]; then
		echo "dae binary is not executable: $binary" >&2
		exit 1
	fi
	binary=$(readlink -f "$binary")
}

refuse_existing_deployment() {
	local resource namespace
	for resource in dae0 ${extra_links[@]+"${extra_links[@]}"}; do
		if ip link show "$resource" >/dev/null 2>&1; then
			echo "$resource already exists; refusing to touch an existing deployment" >&2
			exit 1
		fi
	done
	for namespace in daens ${extra_namespaces[@]+"${extra_namespaces[@]}"}; do
		if ip netns list 2>/dev/null | grep -q "^$namespace"; then
			echo "$namespace already exists; refusing to touch an existing deployment" >&2
			exit 1
		fi
	done
	if [ -e /sys/fs/bpf/dae ]; then
		echo "/sys/fs/bpf/dae already exists; refusing to touch an existing deployment" >&2
		exit 1
	fi
}

ensure_bpffs() {
	if ! mountpoint -q /sys/fs/bpf; then
		mount -t bpf bpf /sys/fs/bpf
		mounted_here=1
	fi
	if [ "$(stat -fc '%T' /sys/fs/bpf)" != "bpf_fs" ]; then
		echo "/sys/fs/bpf is not a bpffs mount" >&2
		exit 1
	fi
}

daemon_has_exited() {
	local pid=$1
	local state
	if ! kill -0 "$pid" 2>/dev/null; then
		return 0
	fi
	state=$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)
	[ "$state" = "Z" ]
}

wait_for_daemon_exit() {
	local pid=$1
	local timeout_seconds=$2
	local deadline=$((SECONDS + timeout_seconds))
	while ! daemon_has_exited "$pid"; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			return 1
		fi
		sleep 1
	done
	wait "$pid" 2>/dev/null || true
}

stop_daemon() {
	local log_file=$1
	local pid=$daemon_pid
	if [ -z "$pid" ]; then
		return 0
	fi
	kill -TERM "$pid" 2>/dev/null || true
	if ! wait_for_daemon_exit "$pid" "$shutdown_timeout_seconds"; then
		echo "daemon did not exit within ${shutdown_timeout_seconds}s" >&2
		if [ -f "$log_file" ]; then
			cat "$log_file" >&2
		fi
		return 1
	fi
	daemon_pid=
}

cleanup() {
	if [ "$cleanup_done" -eq 1 ]; then
		return
	fi
	cleanup_done=1
	set +e
	local pid link namespace
	for pid in "$request_pid" "$client_pid"; do
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill -TERM "$pid" 2>/dev/null
			wait "$pid" 2>/dev/null
		fi
	done
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		if ! wait_for_daemon_exit "$daemon_pid" "$shutdown_timeout_seconds"; then
			kill -KILL "$daemon_pid" 2>/dev/null
			wait_for_daemon_exit "$daemon_pid" 5 || true
		fi
	fi
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
	if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
		kill -TERM "$server_pid" 2>/dev/null
		wait "$server_pid" 2>/dev/null
	fi
	for link in ${extra_links[@]+"${extra_links[@]}"}; do
		ip link del "$link" 2>/dev/null
	done
	for namespace in ${extra_namespaces[@]+"${extra_namespaces[@]}"}; do
		ip netns del "$namespace" 2>/dev/null
	done
	rm -rf /sys/fs/bpf/dae
	if [ "$mounted_here" -eq 1 ]; then
		umount /sys/fs/bpf 2>/dev/null
	fi
	rm -rf "$tmp_dir"
}

start_daemon() {
	local log_file=$1
	"$binary" run -c "$config_file" --disable-sudo --disable-pidfile --disable-timestamp >"$log_file" 2>&1 &
	daemon_pid=$!
}

wait_for_text() {
	local log_file=$1
	local text=$2
	local attempt
	for attempt in {1..45}; do
		if grep -Fq "$text" "$log_file"; then
			return 0
		fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			cat "$log_file" >&2
			return 1
		fi
		sleep 1
	done
	cat "$log_file" >&2
	return 1
}

wait_for_reload_count() {
	local log_file=$1
	local expected=$2
	local attempt finished retired
	# The prefixed log formatter renders "[Reload] Finished" as
	# "Reload: Finished" once ForceFormatting is enabled, which applies to a log
	# file as well as to a terminal. Accept both renderings so this gate tracks
	# reload progress instead of the logger configuration.
	for attempt in {1..45}; do
		finished=$(grep -F -c -e "[Reload] Finished" -e "Reload: Finished" "$log_file" || true)
		retired=$(grep -F -c -e "[Reload] Retired old control plane" -e "Reload: Retired old control plane" "$log_file" || true)
		if [ "$finished" -ge "$expected" ] && [ "$retired" -ge "$expected" ]; then
			return 0
		fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			cat "$log_file" >&2
			return 1
		fi
		sleep 1
	done
	cat "$log_file" >&2
	return 1
}

daemon_fd_count() {
	if ! kill -0 "$daemon_pid" 2>/dev/null; then
		echo "daemon (pid $daemon_pid) exited before an fd-count probe; daemon.log tail:" >&2
		tail -n 40 "$tmp_dir/daemon.log" >&2 2>/dev/null || echo "(daemon log unreadable)" >&2
		dmesg 2>/dev/null | tail -n 20 >&2 || true
		return 1
	fi
	find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l
}

# check_fd_growth <label> fails when the daemon leaked more than 8 fds during
# one reload round and tracks the high-water mark in max_fd_count.
check_fd_growth() {
	local label=$1
	local current
	current=$(daemon_fd_count)
	if [ "$current" -gt "$max_fd_count" ]; then
		max_fd_count=$current
	fi
	if [ "$current" -gt $((baseline_fd_count + 8)) ]; then
		echo "daemon fd count grew from $baseline_fd_count to $current after $label" >&2
		exit 1
	fi
}

# setup_veth_env <server_ns> <host_link> <peer_link> <host_ip> <server_ip>
# creates the deterministic WAN environment shared by all *-local variants.
setup_veth_env() {
	server_ns=$1
	host_link=$2
	peer_link=$3
	host_ip=$4
	server_ip=$5
	ip netns add "$server_ns"
	ip link add "$host_link" type veth peer name "$peer_link"
	ip link set "$peer_link" netns "$server_ns"
	ip addr add "$host_ip/24" dev "$host_link"
	ip link set "$host_link" up
	ip netns exec "$server_ns" ip link set lo up
	ip netns exec "$server_ns" ip addr add "$server_ip/24" dev "$peer_link"
	ip netns exec "$server_ns" ip link set "$peer_link" up
}

write_wan_config() {
	local wan_interface=$1
	config_file="$tmp_dir/config.dae"
	cat >"$config_file" <<EOF
global {
    wan_interface: $wan_interface
    disable_waiting_network: true
}

routing {
    fallback: direct
}
EOF
	chmod 600 "$config_file"
}

# latency_summary_ms <file> <prefix>: min/max/avg over the second TSV column,
# skipping non-numeric rows.
latency_summary_ms() {
	awk -F '\t' -v prefix="$2" '
	($2 ~ /^[0-9]/) {
		total += $2
		if (count == 0 || $2 < minimum) minimum = $2
		if (count == 0 || $2 > maximum) maximum = $2
		count++
	}
	END {
		if (count == 0) exit 1
		printf "%s-ms[min=%.1f max=%.1f avg=%.1f]", prefix, minimum, maximum, total / count
	}' "$1"
}

# latency_summary_connect_total <file>: curl-style TSV with connect seconds in
# column 2 and total seconds in column 3.
latency_summary_connect_total() {
	awk -F '\t' '
	{
		connect += $2 * 1000
		total += $3 * 1000
		if (count == 0 || $2 * 1000 < connect_min) connect_min = $2 * 1000
		if (count == 0 || $2 * 1000 > connect_max) connect_max = $2 * 1000
		if (count == 0 || $3 * 1000 < total_min) total_min = $3 * 1000
		if (count == 0 || $3 * 1000 > total_max) total_max = $3 * 1000
		count++
	}
	END {
		if (count == 0) exit 1
		printf "connect-ms[min=%.1f max=%.1f avg=%.1f] total-ms[min=%.1f max=%.1f avg=%.1f]", connect_min, connect_max, connect / count, total_min, total_max, total / count
	}' "$1"
}

# finish_smoke cleans up, disarms the trap, and asserts that nothing was left
# behind. Call at the end of a successful run.
finish_smoke() {
	cleanup
	trap - EXIT INT TERM
	local link namespace
	for link in ${extra_links[@]+"${extra_links[@]}"}; do
		if ip link show "$link" >/dev/null 2>&1; then
			echo "smoke cleanup left resources behind: $link" >&2
			exit 1
		fi
	done
	for namespace in ${extra_namespaces[@]+"${extra_namespaces[@]}"}; do
		if ip netns list 2>/dev/null | grep -q "^$namespace"; then
			echo "smoke cleanup left resources behind: $namespace" >&2
			exit 1
		fi
	done
	if ip link show dae0 >/dev/null 2>&1 ||
		ip netns list 2>/dev/null | grep -q '^daens' ||
		[ -e /sys/fs/bpf/dae ]; then
		echo "smoke cleanup left dae resources behind" >&2
		exit 1
	fi
}

# ---------------------------------------------------------------------------
# lifecycle: datapath lifecycle and stale-state recovery, no traffic.
# ---------------------------------------------------------------------------
count_daemon_tcx_ingress_links() {
	local count=0 info

	for info in /proc/"$daemon_pid"/fdinfo/*; do
		[ -r "$info" ] || continue
		if grep -Fqx $'link_type:\ttcx' "$info" &&
			grep -Eq '^attach_type:[[:space:]]+[0-9]+ \(ingress\)$' "$info"; then
			count=$((count + 1))
		fi
	done
	printf '%d\n' "$count"
}

assert_internal_tc_hooks() {
	local host_count peer_count tcx_count

	host_count=$(tc filter show dev dae0 ingress | grep -F -c dae_dae0_ingress || true)
	peer_count=$(ip netns exec daens tc filter show dev dae0peer ingress | grep -F -c dae_dae0peer_ingress || true)
	tcx_count=$(count_daemon_tcx_ingress_links)

	if [ "$host_count" -eq 1 ] && [ "$peer_count" -eq 1 ] && [ "$tcx_count" -eq 0 ]; then
		return 0
	fi
	if [ "$host_count" -eq 0 ] && [ "$peer_count" -eq 0 ] && [ "$tcx_count" -eq 2 ]; then
		return 0
	fi

	echo "unexpected internal TC hooks: classic dae0=$host_count dae0peer=$peer_count tcx=$tcx_count" >&2
	return 1
}

run_lifecycle() {
	local source_config rounds
	binary=${1:-$repo_root/dae}
	source_config=${2:-$repo_root/install/empty.dae}
	rounds=${3:-3}
	require_root
	require_commands ip mountpoint stat tc
	require_positive_int rounds "$rounds"
	require_positive_int DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS "$shutdown_timeout_seconds"
	require_binary
	if [ ! -f "$source_config" ]; then
		echo "config file does not exist: $source_config" >&2
		exit 1
	fi
	source_config=$(readlink -f "$source_config")
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.lifecycle.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs

	config_file="$tmp_dir/config.dae"
	cp "$source_config" "$config_file"
	chmod 600 "$config_file"

	local round baseline_rss_kb max_rss_kb current
	start_daemon "$tmp_dir/initial.log"
	wait_for_text "$tmp_dir/initial.log" "Control plane built"
	baseline_rss_kb=$(awk '/^VmRSS:/ { print $2; exit }' "/proc/$daemon_pid/status" 2>/dev/null || true)
	max_rss_kb=$baseline_rss_kb
	if ! [[ "$baseline_rss_kb" =~ ^[0-9]+$ ]]; then
		echo "could not read daemon VmRSS" >&2
		exit 1
	fi

	round=1
	while [ "$round" -le "$rounds" ]; do
		kill -USR1 "$daemon_pid"
		wait_for_reload_count "$tmp_dir/initial.log" "$round"
		if ! assert_internal_tc_hooks; then
			cat "$tmp_dir/initial.log" >&2
			exit 1
		fi
		current=$(awk '/^VmRSS:/ { print $2; exit }' "/proc/$daemon_pid/status" 2>/dev/null || true)
		if [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt "$max_rss_kb" ]; then
			max_rss_kb=$current
		fi
		round=$((round + 1))
	done

	if ! stop_daemon "$tmp_dir/initial.log"; then
		exit 1
	fi

	if [ ! -e /sys/fs/bpf/dae ]; then
		echo "fast-exit did not leave the expected BPF pin root" >&2
		exit 1
	fi
	# Fast exit closes the dae netns: the dae0/dae0peer (veth or netkit) pair
	# and the named daens namespace are removed. Only the BPF pin root is left
	# for the next startup to purge, so a subsequent restart must not trip over
	# them.
	if ip link show dae0 >/dev/null 2>&1; then
		echo "fast-exit did not tear down the expected dae0 device" >&2
		exit 1
	fi
	if ip netns list 2>/dev/null | grep -q '^daens'; then
		echo "fast-exit did not tear down the expected daens namespace" >&2
		exit 1
	fi

	start_daemon "$tmp_dir/recovery.log"
	wait_for_text "$tmp_dir/recovery.log" "Control plane built"
	current=$(awk '/^VmRSS:/ { print $2; exit }' "/proc/$daemon_pid/status" 2>/dev/null || true)
	if [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt "$max_rss_kb" ]; then
		max_rss_kb=$current
	fi
	if ! grep -Fq "purging stale TC filter" "$tmp_dir/recovery.log"; then
		cat "$tmp_dir/recovery.log" >&2
		echo "recovery startup did not purge stale TC state" >&2
		exit 1
	fi

	if ! stop_daemon "$tmp_dir/recovery.log"; then
		exit 1
	fi
	cleanup
	trap - EXIT INT TERM

	echo "semantic refactor lifecycle smoke passed: $rounds reload rounds and stale-state recovery, daemon-rss-baseline=${baseline_rss_kb}KB max=${max_rss_kb}KB"
}

# ---------------------------------------------------------------------------
# Shared reload-round loop for request-during-reload variants. The caller
# provides start_request, which launches a background request writing its
# status to "$status_file" and leaving the pid in request_pid, plus a
# record_result <round> <status_file> consuming the status file.
# ---------------------------------------------------------------------------
run_reload_rounds() {
	local rounds=$1 sleep_before_reload=$2
	local round status_file
	baseline_fd_count=$(daemon_fd_count)
	max_fd_count=$baseline_fd_count
	timing_file="$tmp_dir/timing.tsv"
	round=1
	while [ "$round" -le "$rounds" ]; do
		status_file="$tmp_dir/status-$round"
		request_pid=
		start_request "$round" "$status_file"
		sleep "$sleep_before_reload"
		kill -USR1 "$daemon_pid"
		wait_for_reload_count "$tmp_dir/daemon.log" "$round"
		check_fd_growth "reload round $round"
		if ! wait "$request_pid"; then
			cat "$tmp_dir/daemon.log" >&2
			cat "$status_file" >&2
			echo "request failed during reload round $round" >&2
			exit 1
		fi
		request_pid=
		record_result "$round" "$status_file"
		round=$((round + 1))
	done
}

# ---------------------------------------------------------------------------
# udp-local: deterministic WAN-hook UDP echo with 250ms server delay so every
# request overlaps the reload that follows its send.
# ---------------------------------------------------------------------------
run_udp_local() {
	local rounds
	binary=${1:-$repo_root/dae}
	rounds=${2:-16}
	require_root
	require_commands ip mountpoint python3
	require_positive_int rounds "$rounds"
	require_positive_int DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS "$shutdown_timeout_seconds"
	require_binary

	server_ns=dae-semantic-udp-server
	host_link=dsmoke-udp0
	peer_link=dsmoke-udp-peer
	extra_links=("$host_link")
	extra_namespaces=("$server_ns")
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.udp-local.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	setup_veth_env "$server_ns" "$host_link" "$peer_link" 198.19.0.1 198.19.0.2
	local server_ip=198.19.0.2 server_port=18081

	cat >"$tmp_dir/udp_server.py" <<'PY'
import socket
import sys
import time

address = (sys.argv[1], int(sys.argv[2]))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(address)
while True:
    data, peer = sock.recvfrom(65535)
    if data == b"__stop__":
        break
    time.sleep(0.25)
    sock.sendto(b"echo:" + data, peer)
PY
	cat >"$tmp_dir/udp_client.py" <<'PY'
import socket
import sys
import time

source = sys.argv[1]
target = (sys.argv[2], int(sys.argv[3]))
payload = ("dae-udp-round-" + sys.argv[4]).encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((source, 0))
sock.settimeout(5)
started = time.monotonic()
sock.sendto(payload, target)
data, _ = sock.recvfrom(65535)
elapsed = (time.monotonic() - started) * 1000
if data != b"echo:" + payload:
    raise SystemExit("unexpected UDP echo payload")
print("ok %.1f" % elapsed)
PY

	ip netns exec "$server_ns" python3 -u "$tmp_dir/udp_server.py" "$server_ip" "$server_port" >"$tmp_dir/server.log" 2>&1 &
	server_pid=$!
	local attempt server_ready=0
	for attempt in {1..10}; do
		if python3 "$tmp_dir/udp_client.py" 198.19.0.1 "$server_ip" "$server_port" ready >/dev/null 2>&1; then
			server_ready=1
			break
		fi
		sleep 1
	done
	if [ "$server_ready" -ne 1 ]; then
		cat "$tmp_dir/server.log" >&2
		echo "temporary UDP server did not become ready" >&2
		exit 1
	fi

	write_wan_config "$host_link"

	start_request() {
		python3 "$tmp_dir/udp_client.py" 198.19.0.1 "$server_ip" "$server_port" "$1" >"$2" 2>&1 &
		request_pid=$!
	}
	record_result() {
		local status elapsed
		if ! read -r status elapsed <"$2"; then
			echo "missing UDP timing result in reload round $1" >&2
			exit 1
		fi
		if [ "$status" != "ok" ]; then
			echo "unexpected UDP status in reload round $1: $status" >&2
			exit 1
		fi
		printf '%s\t%s\n' "$1" "$elapsed" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.05

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_ms "$timing_file" echo)
	finish_smoke
	echo "semantic refactor udp-local smoke passed: $rounds veth WAN-hook UDP requests during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# tcp-local: deterministic WAN-hook HTTP transfer against python http.server.
# ---------------------------------------------------------------------------
run_tcp_local() {
	local rounds
	binary=${1:-$repo_root/dae}
	rounds=${2:-16}
	require_root
	require_commands curl dd ip mountpoint python3
	require_positive_int rounds "$rounds"
	require_binary

	server_ns=dae-semantic-tcp-server
	host_link=dsmoke0
	peer_link=dsmoke-peer
	extra_links=("$host_link")
	extra_namespaces=("$server_ns")
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.tcp-local.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	setup_veth_env "$server_ns" "$host_link" "$peer_link" 198.18.0.1 198.18.0.2
	local server_ip=198.18.0.2 server_port=18080

	dd if=/dev/zero of="$tmp_dir/payload" bs=1M count=1 status=none
	ip netns exec "$server_ns" python3 -m http.server "$server_port" --bind "$server_ip" --directory "$tmp_dir" >"$tmp_dir/server.log" 2>&1 &
	server_pid=$!
	local attempt server_ready=0
	for attempt in {1..10}; do
		if curl --noproxy '*' --silent --show-error --fail --head \
			--connect-timeout 1 --max-time 2 "http://$server_ip:$server_port/payload" >/dev/null 2>&1; then
			server_ready=1
			break
		fi
		sleep 1
	done
	if [ "$server_ready" -ne 1 ]; then
		cat "$tmp_dir/server.log" >&2
		echo "temporary TCP server did not become ready" >&2
		exit 1
	fi

	write_wan_config "$host_link"

	start_request() {
		(
			curl --noproxy '*' --silent --show-error --fail \
				--connect-timeout 5 --max-time 30 --limit-rate 128k \
				-o /dev/null -w '%{http_code} %{time_connect} %{time_total}\n' \
				"http://$server_ip:$server_port/payload" >"$2"
		) &
		request_pid=$!
	}
	record_result() {
		local http_code connect_seconds total_seconds
		if ! read -r http_code connect_seconds total_seconds <"$2"; then
			echo "missing curl timing result in reload round $1" >&2
			exit 1
		fi
		if [ "$http_code" != "200" ]; then
			echo "unexpected local HTTP status in reload round $1: $http_code" >&2
			exit 1
		fi
		printf '%s\t%s\t%s\n' "$1" "$connect_seconds" "$total_seconds" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.2

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_connect_total "$timing_file")
	finish_smoke
	echo "semantic refactor tcp-local smoke passed: $rounds veth WAN-hook HTTP requests during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# quic-local: deterministic WAN-hook QUIC datagram echo via the helper.
# ---------------------------------------------------------------------------
run_quic_local() {
	local rounds
	binary=${1:-$repo_root/dae}
	rounds=${2:-8}
	require_root
	require_commands go ip mountpoint
	require_positive_int rounds "$rounds"
	require_binary

	server_ns=dae-semantic-quic-server
	host_link=dsmoke-quic0
	peer_link=dsmq-peer
	extra_links=("$host_link")
	extra_namespaces=("$server_ns")
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.quic-local.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	(cd "$repo_root" && go build -o "$tmp_dir/quic-helper" ./scripts/semantic-refactor-quic-helper)
	setup_veth_env "$server_ns" "$host_link" "$peer_link" 198.20.0.1 198.20.0.2
	local server_ip=198.20.0.2 server_port=18443

	ip netns exec "$server_ns" "$tmp_dir/quic-helper" server "$server_ip" "$server_port" >"$tmp_dir/server.log" 2>&1 &
	server_pid=$!
	local attempt server_ready=0
	for attempt in {1..10}; do
		if "$tmp_dir/quic-helper" client "$server_ip" "$server_port" ready >/dev/null 2>&1; then
			server_ready=1
			break
		fi
		sleep 1
	done
	if [ "$server_ready" -ne 1 ]; then
		cat "$tmp_dir/server.log" >&2
		echo "temporary QUIC server did not become ready" >&2
		exit 1
	fi

	write_wan_config "$host_link"

	start_request() {
		"$tmp_dir/quic-helper" client "$server_ip" "$server_port" "$1" >"$2" 2>&1 &
		request_pid=$!
	}
	record_result() {
		local status elapsed
		if ! read -r status elapsed <"$2" || [ "$status" != "ok" ]; then
			echo "unexpected QUIC result in reload round $1: $(cat "$2")" >&2
			exit 1
		fi
		printf '%s\t%s\n' "$1" "$elapsed" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.1

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_ms "$timing_file" datagram)
	finish_smoke
	echo "semantic refactor quic-local smoke passed: $rounds veth WAN-hook QUIC datagrams during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# iperf-local: TCP and UDP throughput phases, each overlapping one reload.
# ---------------------------------------------------------------------------
run_iperf_local() {
	local duration udp_bitrate
	binary=${1:-$repo_root/dae}
	duration=${2:-3}
	udp_bitrate=${3:-0}
	require_root
	require_commands iperf3 ip mountpoint python3
	require_positive_int duration "$duration"
	if ! [[ "$udp_bitrate" =~ ^(0|[0-9]+([KMG](/[0-9]+)?)?)$ ]]; then
		echo "udp bitrate must be 0 or an iperf3 rate such as 100M" >&2
		exit 1
	fi
	require_binary

	server_ns=dae-semantic-iperf-server
	host_link=dsmoke-iperf0
	peer_link=dsmoke-ipf-peer
	extra_links=("$host_link")
	extra_namespaces=("$server_ns")
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.iperf-local.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	setup_veth_env "$server_ns" "$host_link" "$peer_link" 198.21.0.1 198.21.0.2
	local server_ip=198.21.0.2 tcp_port=19000 udp_port=19001

	write_wan_config "$host_link"

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	baseline_fd_count=$(daemon_fd_count)
	max_fd_count=$baseline_fd_count

	run_iperf() {
		local name=$1 port=$2 protocol=$3 expected_reload=$4
		local client_args=(iperf3 -c "$server_ip" -p "$port" -t "$duration" -J)
		if [ "$protocol" = "udp" ]; then
			client_args+=(-u -b "$udp_bitrate")
		fi
		ip netns exec "$server_ns" iperf3 -s -1 -p "$port" >"$tmp_dir/$name-server.log" 2>&1 &
		server_pid=$!
		sleep 0.3
		"${client_args[@]}" >"$tmp_dir/$name.json" 2>"$tmp_dir/$name-client.log" &
		client_pid=$!
		sleep 0.5
		kill -USR1 "$daemon_pid"
		wait_for_reload_count "$tmp_dir/daemon.log" "$expected_reload"
		check_fd_growth "$name reload"
		if ! wait "$client_pid"; then
			cat "$tmp_dir/$name-client.log" >&2
			exit 1
		fi
		client_pid=
		wait "$server_pid" 2>/dev/null || true
		server_pid=
		python3 - "$tmp_dir/$name.json" "$name" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
end = report["end"]
summary = end.get("sum_received") or end.get("sum")
sent = end.get("sum_sent") or {}
if not summary or summary.get("bits_per_second", 0) <= 0:
    raise SystemExit("iperf3 did not report positive throughput")
loss = summary.get("lost_percent")
jitter = summary.get("jitter_ms")
loss_text = "n/a" if loss is None else f"{loss:.3f}%"
jitter_text = "n/a" if jitter is None else f"{jitter:.3f}ms"
print(
    f"{sys.argv[2]}-rx-bps={summary['bits_per_second']:.0f}"
    f" tx-bps={sent.get('bits_per_second', 0):.0f}"
    f" loss={loss_text} jitter={jitter_text}"
)
PY
	}
	run_iperf tcp "$tcp_port" tcp 1 >"$tmp_dir/tcp-result"
	run_iperf udp "$udp_port" udp 2 >"$tmp_dir/udp-result"

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local tcp_result udp_result
	tcp_result=$(cat "$tmp_dir/tcp-result")
	udp_result=$(cat "$tmp_dir/udp-result")
	finish_smoke
	echo "semantic refactor iperf-local smoke passed: $tcp_result $udp_result, udp-target=$udp_bitrate, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count"
}

# ---------------------------------------------------------------------------
# tcp-public: WAN-hook HTTPS via a pre-resolved public endpoint.
# ---------------------------------------------------------------------------
run_tcp_public() {
	local host rounds target_ip
	binary=${1:-$repo_root/dae}
	host=${2:-example.com}
	rounds=${3:-8}
	require_root
	require_commands curl getent ip mountpoint
	require_positive_int rounds "$rounds"
	require_binary
	target_ip=$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1; exit }')
	if ! [[ "$target_ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
		echo "could not resolve an IPv4 target for $host" >&2
		exit 1
	fi
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.tcp-public.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	write_wan_config auto

	start_request() {
		(
			curl --noproxy '*' -4 --silent --show-error --fail \
				--connect-timeout 5 --max-time 20 \
				--resolve "$host:443:$target_ip" \
				-o /dev/null -w '%{http_code} %{time_connect} %{time_total}\n' "https://$host/" >"$2"
		) &
		request_pid=$!
	}
	record_result() {
		local http_code connect_seconds total_seconds
		if ! read -r http_code connect_seconds total_seconds <"$2"; then
			echo "missing curl timing result in reload round $1" >&2
			exit 1
		fi
		if [ "$http_code" != "200" ]; then
			echo "unexpected HTTP status in reload round $1: $http_code" >&2
			exit 1
		fi
		printf '%s\t%s\t%s\n' "$1" "$connect_seconds" "$total_seconds" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.1

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_connect_total "$timing_file")
	finish_smoke
	echo "semantic refactor tcp-public smoke passed: $rounds WAN-hook HTTPS requests during reload to $host ($target_ip), daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# udp-public: public DNS UDP requests during reload.
# ---------------------------------------------------------------------------
run_udp_public() {
	local resolver rounds
	binary=${1:-$repo_root/dae}
	resolver=${2:-8.8.8.8}
	rounds=${3:-16}
	require_root
	require_commands dig ip mountpoint
	require_positive_int rounds "$rounds"
	require_binary
	if ! [[ "$resolver" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
		echo "resolver must be an IPv4 address" >&2
		exit 1
	fi
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.udp-public.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	write_wan_config auto

	start_request() {
		dig +time=5 +tries=1 "@$resolver" example.com A >"$2" 2>&1 &
		request_pid=$!
	}
	record_result() {
		local query_ms
		if ! grep -Fq "status: NOERROR" "$2" || ! grep -Fq "SERVER: $resolver#53" "$2"; then
			cat "$2" >&2
			exit 1
		fi
		query_ms=$(awk '/Query time:/ { print $4; exit }' "$2")
		printf '%s\t%s\n' "$1" "${query_ms:-unknown}" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.05

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_ms "$timing_file" dns-udp)
	finish_smoke
	echo "semantic refactor udp-public smoke passed: $rounds DNS UDP requests during reload to $resolver:53, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# quic-public: public HTTP/3 requests during reload via the helper.
# ---------------------------------------------------------------------------
run_quic_public() {
	local target rounds
	binary=${1:-$repo_root/dae}
	target=${2:-https://cloudflare-quic.com/}
	rounds=${3:-8}
	require_root
	require_commands go ip mountpoint
	require_positive_int rounds "$rounds"
	require_binary
	if [[ "$target" != https://* ]]; then
		echo "target must use https://" >&2
		exit 1
	fi
	refuse_existing_deployment

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.quic-public.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs
	(cd "$repo_root" && go build -o "$tmp_dir/quic-helper" ./scripts/semantic-refactor-quic-helper)
	write_wan_config auto

	start_request() {
		"$tmp_dir/quic-helper" http3-client "$target" >"$2" 2>"$tmp_dir/request-$1.log" &
		request_pid=$!
	}
	record_result() {
		local protocol_status status_field bytes_field elapsed_field elapsed_value
		read -r protocol_status status_field bytes_field elapsed_field <"$2"
		if [ "$protocol_status" != "http3" ] || [ "$status_field" != "status=200" ]; then
			cat "$2" >&2
			exit 1
		fi
		elapsed_value=${elapsed_field#elapsed-ms=}
		printf '%s\t%s\n' "$1" "$elapsed_value" >>"$timing_file"
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "Control plane built"
	run_reload_rounds "$rounds" 0.1

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	local latency_summary
	latency_summary=$(latency_summary_ms "$timing_file" http3)
	finish_smoke
	echo "semantic refactor quic-public smoke passed: $rounds HTTP/3 requests during reload to $target, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
}

# ---------------------------------------------------------------------------
# dns: DNS listener and cache path against a (public) UDP upstream.
# ---------------------------------------------------------------------------
run_dns() {
	local upstream rounds
	binary=${1:-$repo_root/dae}
	upstream=${2:-8.8.8.8}
	rounds=${3:-1}
	require_root
	require_commands dig ip mountpoint ss
	require_positive_int rounds "$rounds"
	require_binary
	refuse_existing_deployment
	if ss -Hlnup 2>/dev/null | grep -Eq '(^|[[:space:]])127\.0\.0\.1:15353([[:space:]]|$)'; then
		echo "127.0.0.1:15353 is already in use" >&2
		exit 1
	fi

	tmp_dir=$(mktemp -d /tmp/dae-semantic-smoke.dns.XXXXXX)
	trap cleanup EXIT INT TERM
	ensure_bpffs

	config_file="$tmp_dir/config.dae"
	cat >"$config_file" <<EOF
global {
    disable_waiting_network: true
}

routing {}

dns {
    bind: '127.0.0.1:15353'
    upstream {
        smoke: 'udp://$upstream:53'
    }
    routing {
        request {
            fallback: smoke
        }
        response {
            fallback: accept
        }
    }
}
EOF
	chmod 600 "$config_file"

	run_query() {
		local qtype=$1 output=$2 attempt
		for attempt in 1 2 3; do
			if dig +time=3 +tries=1 @127.0.0.1 -p 15353 example.com "$qtype" >"$output" 2>&1 &&
				grep -Fq "status: NOERROR" "$output" &&
				grep -Fq "SERVER: 127.0.0.1#15353" "$output"; then
				return 0
			fi
			sleep 1
		done
		cat "$output" >&2
		return 1
	}

	start_daemon "$tmp_dir/daemon.log"
	wait_for_text "$tmp_dir/daemon.log" "DNS listener started"

	local round
	round=1
	while [ "$round" -le "$rounds" ]; do
		run_query A "$tmp_dir/a-first-$round.log"
		run_query A "$tmp_dir/a-cache-$round.log"
		run_query AAAA "$tmp_dir/aaaa-$round.log"
		round=$((round + 1))
	done

	local a_first_ms a_cache_ms aaaa_ms
	a_first_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/a-first-1.log")
	a_cache_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/a-cache-1.log")
	aaaa_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/aaaa-1.log")

	if ! stop_daemon "$tmp_dir/daemon.log"; then
		exit 1
	fi
	finish_smoke
	echo "semantic refactor dns smoke passed: rounds=$rounds A=${a_first_ms:-unknown} ms cached-A=${a_cache_ms:-unknown} ms AAAA=${aaaa_ms:-unknown} ms"
}

case "${1:-}" in
lifecycle) shift; run_lifecycle "$@" ;;
udp-local) shift; run_udp_local "$@" ;;
tcp-local) shift; run_tcp_local "$@" ;;
quic-local) shift; run_quic_local "$@" ;;
iperf-local) shift; run_iperf_local "$@" ;;
tcp-public) shift; run_tcp_public "$@" ;;
udp-public) shift; run_udp_public "$@" ;;
quic-public) shift; run_quic_public "$@" ;;
dns) shift; run_dns "$@" ;;
*) usage ;;
esac
