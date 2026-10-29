#!/usr/bin/env python3
"""Privileged IPv4 and IPv6 TProxy tests entirely inside three disposable Linux network namespaces."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

# Benchmarking ranges (RFC 2544, RFC 5180): never routed, so a probe cannot leave the namespaces.
TARGETS = {"ipv4": "198.18.0.1", "ipv6": "2001:2::1"}


def run(*argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, capture_output=True, timeout=15, **kwargs)


async def target(args):
    async def echo(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
    class UDP(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
        def datagram_received(self, data, peer):
            self.transport.sendto(data, peer)
    servers, udps = [], []
    for address in TARGETS.values():
        servers.append(await asyncio.start_server(echo, address, args.endpoint))
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=(address, args.endpoint))
        udps.append(udp)
    try:
        await asyncio.sleep(180)
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for udp in udps:
            udp.close()


def probe(endpoint, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        for size in ((1, 32768) if kind == socket.SOCK_STREAM else (1200, 40000)):
            with socket.socket(family, kind) as sock:
                sock.settimeout(8)
                sock.connect((address, endpoint))
                payload = os.urandom(size)
                sock.sendall(payload)
                if kind == socket.SOCK_DGRAM:
                    assert sock.recv(65536) == payload
                else:
                    data = bytearray()
                    while len(data) < size:
                        chunk = sock.recv(size - len(data))
                        assert chunk, "premature transparent TCP EOF"
                        data.extend(chunk)
                    assert data == payload


def qualify(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("requires Linux root/CAP_SYS_ADMIN and network namespace administration")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    args.output = args.output.resolve()
    binary = args.binary.resolve()
    script = Path(__file__).resolve()
    prefix = "twq" + uuid.uuid4().hex[:8]
    client_ns, proxy_ns, server_ns = [prefix + suffix for suffix in ("c", "p", "s")]
    namespaces, processes, logs, results = [], [], [], []
    env = {k: v for k, v in os.environ.items() if not k.startswith("TUNWARD_") and k not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "RUST_LOG")}
    env.update(NO_COLOR="true", SSL_CERT_FILE=str(args.output / "certificates/ca.pem"), SSL_CERT_DIR="")
    def ns(name, *argv, **kwargs):
        return run("ip", "netns", "exec", name, *argv, **kwargs)
    def spawn(name, label, *argv):
        log = (args.output / f"{label}.log").open("wb")
        logs.append(log)
        process = subprocess.Popen(["ip", "netns", "exec", name, *map(str, argv)], stdout=log, stderr=log, env=env)
        processes.append(process)
        return process
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    try:
        for name in (client_ns, proxy_ns, server_ns):
            run("ip", "netns", "add", name)
            namespaces.append(name)
            ns(name, "ip", "link", "set", "lo", "up")
            ns(name, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv4.ip_forward=0",
               "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0")
        # Both ends are created directly in namespaces; no host interface or route is changed.
        ns(client_ns, "ip", "link", "add", "c0", "type", "veth", "peer", "name", "p0", "netns", proxy_ns)
        ns(proxy_ns, "ip", "link", "add", "p1", "type", "veth", "peer", "name", "s0", "netns", server_ns)
        for name, interface, address in ((client_ns, "c0", "10.231.0.2/24"), (proxy_ns, "p0", "10.231.0.1/24"),
                                          (proxy_ns, "p1", "10.232.0.1/24"), (server_ns, "s0", "10.232.0.2/24")):
            ns(name, "ip", "addr", "add", address, "dev", interface)
            ns(name, "ip", "link", "set", interface, "up")
        # IPv6 on the same links; nodad makes the addresses usable at once instead of after duplicate detection.
        for name, interface, address in ((client_ns, "c0", "fd31::2/64"), (proxy_ns, "p0", "fd31::1/64"),
                                          (proxy_ns, "p1", "fd32::1/64"), (server_ns, "s0", "fd32::2/64")):
            ns(name, "ip", "-6", "addr", "add", address, "dev", interface, "nodad")
        ns(client_ns, "ip", "route", "add", "default", "via", "10.231.0.1")
        ns(client_ns, "ip", "-6", "route", "add", "default", "via", "fd31::1")
        ns(server_ns, "ip", "addr", "add", "198.18.0.1/32", "dev", "lo")
        ns(server_ns, "ip", "-6", "addr", "add", "2001:2::1/128", "dev", "lo", "nodad")
        for family, everything in (("-4", "0.0.0.0/0"), ("-6", "::/0")):
            ns(proxy_ns, "ip", family, "rule", "add", "fwmark", "1", "lookup", "100")
            ns(proxy_ns, "ip", family, "route", "add", "local", everything, "dev", "lo", "table", "100")
        rules = """table ip tunward_test {
 chain transparent {
  type filter hook prerouting priority mangle; policy accept;
  iifname "p0" ip daddr 198.18.0.1 meta l4proto tcp tproxy to :15080 meta mark set 1 accept
  iifname "p0" ip daddr 198.18.0.1 meta l4proto udp tproxy to :15081 meta mark set 1 accept
 }
}
table ip6 tunward_test6 {
 chain transparent {
  type filter hook prerouting priority mangle; policy accept;
  iifname "p0" ip6 daddr 2001:2::1 meta l4proto tcp tproxy to :15082 meta mark set 1 accept
  iifname "p0" ip6 daddr 2001:2::1 meta l4proto udp tproxy to :15083 meta mark set 1 accept
 }
}
"""
        (args.output / "rules.nft").write_text(rules)
        ns(proxy_ns, "nft", "-f", "-", input=rules.encode())
        # Issuance stays on the test host; only disposable identities enter the namespaces.
        from qualify_wan import certificates
        asyncio.run(certificates(args.output / "certificates", "10.232.0.2"))
        certs = args.output / "certificates"
        target_process = spawn(server_ns, "target", sys.executable, script, "--target", "--endpoint", "19090")
        policy = args.output / "restrictions.yaml"
        policy.write_text("restrictions:\n - name: TProxy target\n   match: [Any]\n   allow:\n    - !Tunnel\n      protocol: [Tcp, Udp]\n      port: ['19090']\n      cidr: [198.18.0.1/32, 2001:2::1/128]\n")
        server = spawn(server_ns, "server", binary, "server", "--tls-certificate", certs / "server.pem",
                       "--tls-private-key", certs / "server.key", "--tls-client-ca-certs", certs / "ca.pem",
                       "--restrict-config", policy, "--nb-worker-threads", "1", "wts://10.232.0.2:18443")
        time.sleep(0.5)
        for scheme in ("wss", "https", "wts"):
            started = time.monotonic()
            client = spawn(proxy_ns, scheme, binary, "client", "-L", "tproxy+tcp://0.0.0.0:15080",
                           "-L", "tproxy+udp://0.0.0.0:15081?timeout_sec=2",
                           "-L", "tproxy+tcp://[::]:15082", "-L", "tproxy+udp://[::]:15083?timeout_sec=2",
                           "--tls-certificate", certs / "client.pem",
                           "--tls-private-key", certs / "client.key", "--tls-verify-certificate",
                           "--nb-worker-threads", "1", f"{scheme}://10.232.0.2:18443")
            try:
                time.sleep(0.5)
                for family, address in TARGETS.items():
                    try:
                        assert server.poll() is None and client.poll() is None and target_process.poll() is None, "fixture exited; inspect logs"
                        ns(client_ns, sys.executable, script, "--probe", "--endpoint", "19090", "--address", address)
                        results.append({"name": f"tproxy/{scheme}/{family}-tcp-udp", "status": "pass",
                                        "elapsed_seconds": round(time.monotonic() - started, 3),
                                        "tcp_bytes": [1, 32768], "udp_datagram_bytes": [1200, 40000],
                                        "original_destination_and_reply_source_preserved": True, "proxy_ip_forward": False})
                    except Exception as exc:
                        detail = exc.stderr.decode(errors="replace")[-500:] if isinstance(exc, subprocess.CalledProcessError) else str(exc)
                        results.append({"name": f"tproxy/{scheme}/{family}-tcp-udp", "status": "fail", "error": detail})
            finally:
                stop(client)
        ns(proxy_ns, "nft", "list", "ruleset")
    finally:
        for process in reversed(processes):
            stop(process)
        for log in logs:
            log.close()
        for name in reversed(namespaces):
            run("ip", "netns", "del", name)
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        (args.output / "metadata.json").write_text(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "runner_sha256": hashlib.sha256(script.read_bytes()).hexdigest(), "namespaces": namespaces,
            "cleaned_up": True, "scope": "Linux IPv4 and IPv6 TProxy TCP/UDP; three disposable namespaces; no host routes/firewall changes; not host firewall integration"}, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    return len(results) != 3 * len(TARGETS) or any(r["status"] != "pass" for r in results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint", type=int, default=19090, help=argparse.SUPPRESS)
    parser.add_argument("--address", default=TARGETS["ipv4"], help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.target:
        asyncio.run(target(args))
    elif args.probe:
        probe(args.endpoint, args.address)
    elif args.output:
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        raise SystemExit(bool(qualify(args)))
    else:
        parser.error("--output is required")


if __name__ == "__main__":
    main()
