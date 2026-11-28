# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request


CLIENT_IP = '192.0.2.2'
SERVER_IP = '198.18.0.2'
SERVER_PORT = 18082
SHARED_FIELDS = (
    'chain', 'chain_source', 'rule_id', 'rule_expression', 'rule_source',
    'ingress', 'domain_source',
)
PAYLOAD = b'GET / HTTP/1.1\r\nHost: flow-rule.invalid\r\n\r\n'
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def serve():
    address = (SERVER_IP, SERVER_PORT)
    with socketserver.ThreadingTCPServer(address, TCP) as tcp, socketserver.UDPServer(address, UDP) as udp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        udp.serve_forever()


def client(network):
    kind = socket.SOCK_STREAM if network == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(5)
        sock.bind((CLIENT_IP, 0))
        sock.connect((SERVER_IP, SERVER_PORT))
        port = sock.getsockname()[1]
        for _ in sys.stdin:
            sock.sendall(PAYLOAD)
            received = b''
            while len(received) < len(PAYLOAD):
                data = sock.recv(4096)
                if not data:
                    raise EOFError('echo socket closed')
                received += data
            assert received == PAYLOAD, received
            print(port, flush=True)


@contextmanager
def connection(namespace, network):
    with subprocess.Popen(
        ['ip', 'netns', 'exec', namespace, sys.executable, __file__, network],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    ) as process:
        try:
            yield process
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


def exchange(process):
    process.stdin.write('echo\n')
    process.stdin.flush()
    if not select.select([process.stdout], [], [], 7)[0]:
        raise TimeoutError('local echo did not finish')
    return int(process.stdout.readline())


def get(path):
    with HTTP.open(f"http://127.0.0.1:19527/api/v1/{path}", timeout=2) as reply:
        return json.load(reply)


def wait_for(description, get_value):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if value := get_value():
                return value
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {description}")


def check_connection(network, port, rules, expected_index):
    def find_connection():
        response = get('connections')
        for row in response[network]:
            if row['src'] == f"{CLIENT_IP}:{port}":
                return response['instance_id'], row

    instance_id, connection = wait_for(f"active {network} connection on {port}", find_connection)
    flow_id = connection['flow_id']
    connection_id = connection['id']
    assert flow_id and connection_id and connection['state'] == 'active', connection
    assert 'rule_generation_id' not in connection, connection
    summary = next(row for row in get(f"flows?connection_id={connection_id}&state=active")['flows']
                   if row['id'] == flow_id)
    detail = get(f"flows/{flow_id}")
    rule = rules['rules'][expected_index]
    assert rule['rule_id'] and rule['expression'] and rules['generation_id'], rules
    assert connection['rule_id'] == rule['rule_id'], (network, connection, rule)
    assert connection['rule_expression'] == rule['expression'], (network, connection, rule)
    assert connection['rule_source'] == 'userspace', (network, connection)
    for row in (summary, detail):
        assert (row['id'], row['connection_id'], row['state'], row['network']) == (
            flow_id, connection_id, 'active', network,
        ), row
        assert row['instance_id'] == instance_id, row
        assert row['rule_generation_id'] == rules['generation_id'], (network, row, rules)
        for key in SHARED_FIELDS:
            assert row[key] == connection[key], (network, key, row[key], connection[key])
    return connection_id, flow_id


def check(namespace, config, daemon_pid):
    before = wait_for('first rule dictionary', lambda: get('rules'))
    # TCP's HTTP Host matches the explicit domain rule. Plain UDP reaches the
    # selector-only rule after the same LAN sniff-punt.
    expected_indices = {'tcp': 1, 'udp': 2}
    with ExitStack() as clients:
        old = {}
        for network, index in expected_indices.items():
            process = clients.enter_context(connection(namespace, network))
            port = exchange(process)
            old[network] = (process, port, check_connection(network, port, before, index))

        # Shift the expected rule IDs by one so retaining only the current
        # dictionary cannot satisfy the assertions for the held connections.
        updated = config.read_text().replace('routing {\n', 'routing {\n    dport(1) -> block\n', 1)
        config.write_text(updated)
        os.kill(daemon_pid, signal.SIGUSR1)

        def new_rules():
            rules = get('rules')
            return rules if rules['generation_id'] != before['generation_id'] else None

        after = wait_for('new rule dictionary', new_rules)
        for network, index in expected_indices.items():
            process, port, ids = old[network]
            assert exchange(process) == port
            assert check_connection(network, port, before, index) == ids
            fresh = clients.enter_context(connection(namespace, network))
            fresh_ids = check_connection(network, exchange(fresh), after, index + 1)
            assert fresh_ids != ids, (network, ids, fresh_ids)
            print(f"{network}: three native API responses agree for held and new active flows", flush=True)


if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'server':
        serve()
    elif mode == 'check':
        check(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]))
    else:
        client(mode)
