#!/usr/bin/env python3
"""Qualify restriction CIDR confinement of domain destinations and the bounds on connections that
have not authenticated yet. Exit 1 means a measured check failed.

Run: python3 scripts/qualify_hardening.py --binary target/release/tunward --output target/qualification/hardening
Loopback only: no external targets, firewall changes, or privileged operations. Needs OpenSSL.
"""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import socket
import struct
import subprocess
import sys
import time

from qualify import EchoUDP, Suite, close, port, stats
from qualify_wan import certificates, echo


class Counter:
    """TCP endpoint that a denied tunnel must never reach."""

    def __init__(self):
        self.connections = 0

    async def handle(self, reader, writer):
        self.connections += 1
        await close(writer)


class CountingUDP(asyncio.DatagramProtocol):
    """UDP endpoint that a denied tunnel must never reach."""

    def __init__(self):
        self.datagrams = 0

    def datagram_received(self, data, addr):
        self.datagrams += 1


class RebindingDNS(asyncio.DatagramProtocol):
    """Answers the n-th A query with answers[n] (the last one repeats) and a zero TTL."""

    def __init__(self, answers):
        self.answers = answers
        self.a_queries = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        end = 12
        while end < len(data) and data[end] != 0:
            end += 1 + data[end]
        if end + 5 > len(data):
            return
        answer = None
        if struct.unpack("!H", data[end + 1:end + 3])[0] == 1:
            answer = self.answers[min(self.a_queries, len(self.answers) - 1)]
            self.a_queries += 1
        response = data[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if answer else 0, 0, 0) + data[12:end + 5]
        if answer:
            response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(answer)
        self.transport.sendto(response, addr)


def quic_client_supported(openssl):
    try:
        result = subprocess.run([openssl, "s_client", "-help"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "-quic" in result.stdout + result.stderr


def limit_descriptors(limit):
    def apply():
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    return apply


class Hardening:
    def __init__(self, args):
        self.args = args
        self.suite = Suite(args)
        self.out = self.suite.out
        self.certs = self.out / "certificates"
        self.servers = []
        self.datagram_transports = []

    def quic_client_version(self):
        try:
            return subprocess.run([self.args.openssl, "version"], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None

    def record(self, name, status="pass", **data):
        self.suite.record(name, status, **data)

    def server_tls(self):
        return ["--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--tls-client-ca-certs", str(self.certs / "ca.pem")]

    def client_tls(self):
        return ["--tls-verify-certificate", "--tls-certificate", str(self.certs / "client.pem"),
                "--tls-private-key", str(self.certs / "client.key")]

    def ca_env(self):
        return {"SSL_CERT_FILE": str(self.certs / "ca.pem"), "SSL_CERT_DIR": ""}

    def log(self, label):
        return (self.out / f"{label}.log").read_text(errors="replace")

    async def tcp_endpoint(self, handler, host="127.0.0.1", bind_port=0):
        server = await asyncio.start_server(handler, host, bind_port)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def udp_endpoint(self, factory):
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            factory, local_addr=("127.0.0.1", 0))
        self.datagram_transports.append(transport)
        return transport.get_extra_info("sockname")[1], protocol

    async def listening(self, endpoint, process, udp=False):
        # A connecting readiness probe would itself open a tunnel, so watch the socket tables instead.
        table = Path("/proc/net/udp" if udp else "/proc/net/tcp")
        state = "07" if udp else "0A"
        for _ in range(500):
            if process.returncode is not None:
                raise RuntimeError(f"process exited {process.returncode}; see logs")
            if not table.exists():
                await asyncio.sleep(1)
                return
            if any(int(row.split()[1].rsplit(":", 1)[1], 16) == endpoint and row.split()[3] == state
                   for row in table.read_text().splitlines()[1:]):
                return
            await asyncio.sleep(0.01)
        raise TimeoutError(f"listener {endpoint} unavailable")

    async def reaches(self, endpoint, size=1024):
        latency_ms = await asyncio.wait_for(self.suite.exchange("tcp", endpoint, size), 10)
        return {"allowed": True, "round_trip_ms": round(latency_ms, 3)}

    async def denied(self, endpoint, counter=None):
        before = counter.connections if counter else 0
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            writer.write(b"denied")
            await writer.drain()
            received = await asyncio.wait_for(reader.read(16), 10)
            assert received == b"", f"a denied tunnel delivered {received!r}"
        except ConnectionError:
            pass
        finally:
            await close(writer)
        await asyncio.sleep(0.3)
        if counter:
            assert counter.connections == before, f"the forbidden endpoint was reached {counter.connections - before} time(s)"
        return {"allowed": False, "forbidden_endpoint_connections": counter.connections if counter else None}

    async def udp_denied(self, endpoint, counter, server_label, destination_port, datagrams=3):
        def rejections():
            return sum("not allowed destination" in line and f"port: {destination_port} " in line
                       for line in self.log(server_label).splitlines())
        before = rejections()
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            sock.connect(("127.0.0.1", endpoint))
            for _ in range(datagrams):
                await loop.sock_sendall(sock, b"denied")
                await asyncio.sleep(0.05)
            try:
                reply = await asyncio.wait_for(loop.sock_recv(sock, 64), 3)
                raise AssertionError(f"a denied UDP tunnel replied {reply!r}")
            except asyncio.TimeoutError:
                pass
        assert counter.datagrams == 0, f"the forbidden UDP endpoint received {counter.datagrams} datagram(s)"
        # A refused tunnel must not leave its datagram queued to be retried endlessly.
        attempts = rejections() - before
        assert 1 <= attempts <= datagrams, f"{attempts} tunnel attempts for {datagrams} datagrams"
        return {"allowed": False, "forbidden_endpoint_datagrams": counter.datagrams,
                "datagrams_sent": datagrams, "tunnel_attempts_rejected": attempts}

    async def prepare(self):
        await certificates(self.certs, "127.0.0.1")
        self.echo_port = await self.tcp_endpoint(echo)
        self.udp_echo_port, _ = await self.udp_endpoint(EchoUDP)
        self.suite.echo_port = self.echo_port
        self.decoy, self.mapped_decoy = Counter(), Counter()
        self.decoy_port = await self.tcp_endpoint(self.decoy.handle)
        self.mapped_decoy_port = await self.tcp_endpoint(self.mapped_decoy.handle)
        self.decoy_udp_port, self.decoy_udp = await self.udp_endpoint(CountingUDP)
        self.reverse_port = port()
        self.policy = self.out / "restrictions.yaml"
        self.policy.write_text(f"""restrictions:
  - name: hardening
    match: [Any]
    allow:
      - !Tunnel
        port: ["{self.echo_port}", "{self.udp_echo_port}"]
        cidr: [127.0.0.1/32]
      - !Tunnel
        port: ["{self.decoy_port}", "{self.decoy_udp_port}"]
        cidr: [10.0.0.0/8]
      - !Tunnel
        port: ["{self.mapped_decoy_port}"]
        cidr: ["::/0"]
      - !ReverseTunnel
        protocol: [Tcp]
        port: ["{self.reverse_port}"]
        cidr: [127.0.0.1/32]
""")

    async def cidr(self):
        plain_port, tls_port = port(), port()
        plain = await self.suite.spawn("cidr-ws-server", "server", f"ws://127.0.0.1:{plain_port}",
                                       "--restrict-config", str(self.policy))
        mtls = await self.suite.spawn("cidr-mtls-server", "server", f"wts://127.0.0.1:{tls_port}",
                                      "--restrict-config", str(self.policy), *self.server_tls())
        await self.suite.ready(plain_port, plain)
        await self.suite.ready(tls_port, mtls)
        try:
            for scheme in ("ws", "wss", "https", "wts"):
                ep = {name: port() for name in ("inside", "outside", "literal", "mapped", "udp-inside", "udp-outside")}
                specs = ["-L", f"tcp://127.0.0.1:{ep['inside']}:localhost:{self.echo_port}",
                         "-L", f"tcp://127.0.0.1:{ep['outside']}:localhost:{self.decoy_port}",
                         "-L", f"tcp://127.0.0.1:{ep['literal']}:127.0.0.1:{self.decoy_port}",
                         "-L", f"tcp://127.0.0.1:{ep['mapped']}:[::ffff:127.0.0.1]:{self.mapped_decoy_port}",
                         "-L", f"udp://127.0.0.1:{ep['udp-inside']}:localhost:{self.udp_echo_port}?timeout_sec=5",
                         "-L", f"udp://127.0.0.1:{ep['udp-outside']}:localhost:{self.decoy_udp_port}?timeout_sec=5"]
                tls = [] if scheme == "ws" else self.client_tls()
                server_port = plain_port if scheme == "ws" else tls_port
                client = await self.suite.spawn(f"cidr-{scheme}-client", "client", *specs, *tls,
                                                "--connection-retry-max-backoff", "2s",
                                                f"{scheme}://127.0.0.1:{server_port}", extra_env=self.ca_env())
                try:
                    for name in ("inside", "outside", "literal", "mapped"):
                        await self.listening(ep[name], client)
                    for name in ("udp-inside", "udp-outside"):
                        await self.listening(ep[name], client, udp=True)
                    await self.suite.check(f"cidr/{scheme}/tcp/domain-inside-cidr-allowed",
                                           lambda e=ep["inside"]: self.reaches(e))
                    await self.suite.check(f"cidr/{scheme}/tcp/domain-outside-cidr-denied",
                                           lambda e=ep["outside"]: self.denied(e, self.decoy))
                    await self.suite.check(f"cidr/{scheme}/tcp/address-outside-cidr-denied",
                                           lambda e=ep["literal"]: self.denied(e, self.decoy))
                    await self.suite.check(f"cidr/{scheme}/tcp/ipv4-mapped-follows-ipv4-rules",
                                           lambda e=ep["mapped"]: self.denied(e, self.mapped_decoy))
                    await self.suite.check(f"cidr/{scheme}/udp/domain-inside-cidr-allowed",
                                           lambda e=ep["udp-inside"]: self.suite.udp(e, 64, 4), 15)
                    server_label = "cidr-ws-server" if scheme == "ws" else "cidr-mtls-server"
                    await self.suite.check(f"cidr/{scheme}/udp/domain-outside-cidr-denied-without-retry-storm",
                                           lambda e=ep["udp-outside"], l=server_label: self.udp_denied(
                                               e, self.decoy_udp, l, self.decoy_udp_port))
                finally:
                    await self.suite.stop(client)
        finally:
            await self.suite.stop(plain)
            await self.suite.stop(mtls)
        reasons = sum(self.log(label).count("outside the allowed CIDRs") for label in ("cidr-ws-server", "cidr-mtls-server"))
        self.record("cidr/rejection-reason-logged", "pass" if reasons else "fail", domain_rejections_logged=reasons)

    async def restrict_to_hostname(self):
        sp = port()
        server = await self.suite.spawn("compat-server", "server", f"ws://127.0.0.1:{sp}",
                                        "--restrict-to", f"localhost:{self.echo_port}")
        name, literal = port(), port()
        try:
            await self.suite.ready(sp, server)
            client = await self.suite.spawn("compat-client", "client",
                                            "-L", f"tcp://127.0.0.1:{name}:localhost:{self.echo_port}",
                                            "-L", f"tcp://127.0.0.1:{literal}:127.0.0.1:{self.echo_port}",
                                            "--connection-retry-max-backoff", "2s", f"ws://127.0.0.1:{sp}")
            await self.listening(name, client)
            await self.listening(literal, client)
            await self.suite.check("compat/restrict-to-hostname/name-allowed", lambda: self.reaches(name))
            await self.suite.check("compat/restrict-to-hostname/literal-address-denied", lambda: self.denied(literal))
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    async def rebinding(self):
        if not sys.platform.startswith("linux"):
            self.record("dns-rebinding/pinned", "not_run", reason="needs 127.0.0.2 on loopback (Linux)")
            return
        allowed_port = await self.tcp_endpoint(echo)
        forbidden = Counter()
        await self.tcp_endpoint(forbidden.handle, "127.0.0.2", allowed_port)
        loop = asyncio.get_running_loop()
        dns_transport, dns = await loop.create_datagram_endpoint(
            lambda: RebindingDNS(["127.0.0.1", "127.0.0.2"]), local_addr=("127.0.0.1", 0))
        self.datagram_transports.append(dns_transport)
        dns_port = dns_transport.get_extra_info("sockname")[1]
        policy = self.out / "rebinding-restrictions.yaml"
        policy.write_text(f"restrictions:\n  - name: pinned\n    match: [Any]\n    allow:\n      - !Tunnel\n"
                          f"        port: [\"{allowed_port}\"]\n        cidr: [127.0.0.1/32]\n")
        sp, lp = port(), port()
        server = await self.suite.spawn("rebinding-server", "server", f"ws://127.0.0.1:{sp}",
                                        "--restrict-config", str(policy), "--dns-resolver", f"dns://127.0.0.1:{dns_port}")
        try:
            await self.suite.ready(sp, server)
            client = await self.suite.spawn("rebinding-client", "client",
                                            "-L", f"tcp://127.0.0.1:{lp}:rebind.tunward.test:{allowed_port}",
                                            "--connection-retry-max-backoff", "2s", f"ws://127.0.0.1:{sp}")
            await self.listening(lp, client)

            async def pinned():
                details = await self.reaches(lp)
                assert forbidden.connections == 0, "the rebound address was dialed"
                assert dns.a_queries == 1, f"expected one lookup for the tunnel, observed {dns.a_queries}"
                return {**details, "a_queries": dns.a_queries, "forbidden_endpoint_connections": forbidden.connections}
            await self.suite.check("dns-rebinding/connection-uses-checked-address", pinned)

            async def rebound():
                details = await self.denied(lp, forbidden)
                assert dns.a_queries == 2, f"expected a fresh lookup for the second tunnel, observed {dns.a_queries}"
                return {**details, "a_queries": dns.a_queries}
            await self.suite.check("dns-rebinding/rebound-name-denied", rebound)
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    async def handshake_timeout(self):
        sp = port()
        server = await self.suite.spawn("handshake-timeout-server", "server", f"wss://127.0.0.1:{sp}",
                                        "--restrict-config", str(self.policy), *self.server_tls(),
                                        "--tls-handshake-timeout", "2s")
        try:
            await self.suite.ready(sp, server)

            async def idle():
                reader, writer = await asyncio.open_connection("127.0.0.1", sp)
                started = time.monotonic()
                try:
                    received = await asyncio.wait_for(reader.read(1), 15)
                except ConnectionError:
                    received = b""
                finally:
                    await close(writer)
                elapsed = time.monotonic() - started
                assert received == b"", received
                assert 1.5 <= elapsed <= 5, f"closed after {elapsed:.2f}s, expected about 2s"
                await asyncio.sleep(0.2)
                assert "did not complete within 2s" in self.log("handshake-timeout-server")
                return {"closed_after_seconds": round(elapsed, 3), "configured_timeout_seconds": 2}
            await self.suite.check("handshake/idle-connection-closed-by-timeout", idle)
        finally:
            await self.suite.stop(server)

    async def pending_limit(self):
        sp, lp = port(), port()
        server = await self.suite.spawn("pending-limit-server", "server", f"wss://127.0.0.1:{sp}",
                                        "--restrict-config", str(self.policy), *self.server_tls(),
                                        "--max-pending-tls-handshakes", "4", "--tls-handshake-timeout", "4s")
        idle = []
        try:
            await self.suite.ready(sp, server)
            client = await self.suite.spawn("pending-limit-client", "client",
                                            "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}", *self.client_tls(),
                                            "--connection-retry-max-backoff", "2s", f"wss://127.0.0.1:{sp}",
                                            extra_env=self.ca_env())
            await self.listening(lp, client)
            session_reader, session_writer = await self.suite.connect("tcp", lp)

            async def roundtrip(data):
                session_writer.write(data)
                await session_writer.drain()
                assert await asyncio.wait_for(session_reader.readexactly(len(data)), 5) == data

            async def flood():
                await roundtrip(b"before-flood")
                for _ in range(4):
                    idle.append(await asyncio.open_connection("127.0.0.1", sp))
                await asyncio.sleep(0.5)
                reader, writer = await asyncio.open_connection("127.0.0.1", sp)
                started = time.monotonic()
                try:
                    received = await asyncio.wait_for(reader.read(1), 2)
                except ConnectionError:
                    received = b""
                finally:
                    await close(writer)
                shed_seconds = time.monotonic() - started
                assert received == b"" and shed_seconds < 1, f"excess handshake held for {shed_seconds:.2f}s"
                await roundtrip(b"during-flood")
                await asyncio.sleep(0.2)
                assert "TLS handshakes already pending" in self.log("pending-limit-server")
                return {"pending_limit": 4, "excess_closed_after_seconds": round(shed_seconds, 3),
                        "established_session_forwarding_during_flood": True}
            await self.suite.check("handshake/excess-closed-established-session-unaffected", flood, 15)

            async def recovery():
                started = time.monotonic()
                for reader, writer in idle:
                    try:
                        assert await asyncio.wait_for(reader.read(1), 12) == b""
                    except ConnectionError:
                        pass
                    await close(writer)
                closed_after = time.monotonic() - started
                details = await self.reaches(lp)
                await roundtrip(b"after-recovery")
                return {**details, "pending_closed_after_seconds": round(closed_after, 3)}
            await self.suite.check("handshake/slots-recover-after-timeout", recovery, 25)
            self.suite.owned_writers.discard(session_writer)
            await close(session_writer)
        finally:
            for _, writer in idle:
                await close(writer)
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    async def quic_without_request(self, server_port):
        """An mTLS QUIC client that completes its handshake, then never sends an HTTP/3 request."""
        self.quic_clients = getattr(self, "quic_clients", 0) + 1
        output = self.out / f"quic-client-{self.quic_clients}.out"
        with open(output, "wb") as log:
            process = await asyncio.create_subprocess_exec(
                self.args.openssl, "s_client", "-quic", "-alpn", "h3", "-connect", f"127.0.0.1:{server_port}",
                "-servername", "localhost", "-CAfile", str(self.certs / "ca.pem"),
                "-cert", str(self.certs / "client.pem"), "-key", str(self.certs / "client.key"),
                # An open, silent stdin keeps the client connected without sending anything.
                stdin=asyncio.subprocess.PIPE, stdout=log, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True)
        self.quic_processes.append(process)
        return process, output

    @staticmethod
    def handshake_completed(output):
        return b"ALPN protocol: h3" in output.read_bytes()

    async def until_handshake(self, process, output, timeout=10):
        deadline = time.monotonic() + timeout
        while not self.handshake_completed(output):
            assert process.returncode is None, "the QUIC client exited before completing its handshake"
            assert time.monotonic() < deadline, "the QUIC handshake did not complete"
            await asyncio.sleep(0.05)

    async def quic_bounds(self):
        if not quic_client_supported(self.args.openssl):
            # --require-quic turns a missing client into a failure, so CI cannot silently skip this.
            self.record("handshake/quic/suite", "fail" if self.args.require_quic else "not_run",
                        reason=f"{self.args.openssl} s_client has no -quic (OpenSSL 3.5+ needed); the Rust test "
                               "test_webtransport_handshakes_are_bounded_without_affecting_sessions covers this path")
            return
        self.quic_processes = []
        sp, lp = port(), port()
        # Pings off disables QUIC's own idle timeout, so only the handshake bounds can close a peer.
        server = await self.suite.spawn("quic-bounds-server", "server", f"wts://127.0.0.1:{sp}",
                                        "--restrict-config", str(self.policy), *self.server_tls(),
                                        "--tls-handshake-timeout", "2s", "--max-pending-tls-handshakes", "3",
                                        "--websocket-ping-frequency", "0")
        try:
            await self.suite.ready(sp, server)
            await self.listening(sp, server, udp=True)
            client = await self.suite.spawn("quic-bounds-client", "client",
                                            "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}", *self.client_tls(),
                                            "--connection-retry-max-backoff", "2s", f"wts://127.0.0.1:{sp}",
                                            extra_env=self.ca_env())
            await self.listening(lp, client)
            session_reader, session_writer = await self.suite.connect("tcp", lp)

            async def roundtrip(data):
                session_writer.write(data)
                await session_writer.drain()
                assert await asyncio.wait_for(session_reader.readexactly(len(data)), 5) == data

            async def idle_closed():
                await roundtrip(b"before")
                process, output = await self.quic_without_request(sp)
                started = time.monotonic()
                await self.until_handshake(process, output)
                await asyncio.wait_for(process.wait(), 15)
                elapsed = time.monotonic() - started
                assert 1.5 <= elapsed <= 6, f"closed after {elapsed:.2f}s, expected about 2s"
                await asyncio.sleep(0.2)
                assert "QUIC/HTTP3 handshake did not complete within 2s" in self.log("quic-bounds-server")
                return {"authenticated_quic_handshake": True, "closed_after_seconds": round(elapsed, 3),
                        "configured_timeout_seconds": 2, "server_quic_idle_timeout": "disabled"}
            await self.suite.check("handshake/quic/idle-session-request-closed-by-timeout", idle_closed, 25)

            pending = []

            async def flood():
                for _ in range(3):
                    process, output = await self.quic_without_request(sp)
                    await self.until_handshake(process, output)
                    pending.append(process)
                process, output = await self.quic_without_request(sp)
                await asyncio.wait_for(process.wait(), 10)
                assert not self.handshake_completed(output), "a connection beyond the limit completed its handshake"
                await asyncio.sleep(0.2)
                assert "Refusing webtransport connection" in self.log("quic-bounds-server")
                await roundtrip(b"during")
                details = await self.reaches(lp)
                return {"pending_limit": 3, "excess_refused": True,
                        "established_session_forwarding_during_flood": True, "new_tunnel_on_session": details}
            await self.suite.check("handshake/quic/excess-refused-established-session-unaffected", flood, 40)

            async def recovered():
                started = time.monotonic()
                for process in pending:
                    await asyncio.wait_for(process.wait(), 10)
                closed_after = time.monotonic() - started
                process, output = await self.quic_without_request(sp)
                await self.until_handshake(process, output)
                process.kill()
                await process.wait()
                await roundtrip(b"after")
                return {"pending_closed_within_seconds": round(closed_after, 3), "new_handshake_accepted": True}
            await self.suite.check("handshake/quic/slots-recover-after-timeout", recovered, 30)
            self.suite.owned_writers.discard(session_writer)
            await close(session_writer)
        finally:
            for process in self.quic_processes:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    @staticmethod
    def flood(targets, per_target):
        sockets = []
        for target in targets:
            for _ in range(per_target):
                try:
                    sockets.append(socket.create_connection(("127.0.0.1", target), timeout=1))
                except OSError:
                    break
        return sockets

    async def exhausted(self, label, process, flood_connections, accept_loops, cpu_limit=0.3, window=3):
        """Measure a process that ran out of descriptors: it must neither spin nor flood its log.

        Each accept loop may log once per ten seconds. Tunnels opened for flood connections that were
        accepted may log their own failure once, so the total is bounded by the flood, not by time.
        """
        await asyncio.sleep(1.5)
        log = self.out / f"{label}.log"

        def counts():
            text = log.read_text(errors="replace")
            return text.count("\n"), text.count("pausing accepts")
        (lines_before, accepts_before), before = counts(), stats(process.pid)
        await asyncio.sleep(window)
        (lines_after, accepts_after), after = counts(), stats(process.pid)
        assert process.returncode is None, "the process exited while out of descriptors"
        assert "Too many open files" in log.read_text(errors="replace"), "descriptor exhaustion was not reached"
        details = {"window_seconds": window, "log_lines": lines_after - lines_before,
                   "accept_error_lines": accepts_after - accepts_before, "fds": after.get("fds")}
        assert details["accept_error_lines"] <= 2 * accept_loops, f"{details['accept_error_lines']} accept error lines in {window}s"
        assert details["log_lines"] <= flood_connections + 20, f"{details['log_lines']} log lines in {window}s"
        if before and after:
            details["cpu_seconds"] = round(after["cpu_seconds"] - before["cpu_seconds"], 3)
            assert details["cpu_seconds"] <= cpu_limit, f"{details['cpu_seconds']} CPU seconds in {window}s"
        return details

    async def server_descriptors(self):
        sp, mp, lp = port(), port(), port()
        server = await self.suite.spawn("fd-server", "server", f"ws://127.0.0.1:{sp}", "--management-api", f"127.0.0.1:{mp}",
                                        "--restrict-config", str(self.policy), log_level="WARN",
                                        preexec_fn=limit_descriptors(self.args.fd_limit))
        sockets = []
        try:
            await self.suite.ready(sp, server)
            client = await self.suite.spawn("fd-server-client", "client",
                                            "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}",
                                            "-R", f"tcp://127.0.0.1:{self.reverse_port}:127.0.0.1:{self.echo_port}",
                                            "--connection-retry-max-backoff", "2s",
                                            "--reverse-tunnel-connection-retry-max-backoff", "1s", f"ws://127.0.0.1:{sp}")
            await self.listening(lp, client)
            await self.listening(self.reverse_port, server)
            await self.suite.check("fd-exhaustion/server/baseline", lambda: self.reaches(lp))

            async def exhausted():
                # The tunnel listener runs out first; the management API and reverse listener then
                # keep failing to accept their own pending connections too.
                sockets.extend(await asyncio.to_thread(self.flood, (sp, mp, self.reverse_port), 2 * self.args.fd_limit))
                details = await self.exhausted("fd-server", server, len(sockets), accept_loops=3)
                return {**details, "flood_connections": len(sockets), "fd_limit": self.args.fd_limit,
                        "listeners": ["tunnel", "management-api", "reverse-tcp"]}
            await self.suite.check("fd-exhaustion/server/no-spin-no-log-flood", exhausted, 30)

            async def recovered():
                for sock in sockets:
                    sock.close()
                sockets.clear()
                deadline = time.monotonic() + 15
                while True:
                    try:
                        health = await asyncio.wait_for(self.suite.api(mp, "/healthz"), 3)
                        forward = await self.reaches(lp)
                        reverse = await self.reaches(self.reverse_port)
                        return {"health": health["status"], "forward": forward, "reverse": reverse}
                    except (OSError, AssertionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                        if time.monotonic() > deadline:
                            raise
                        await asyncio.sleep(0.5)
            await self.suite.check("fd-exhaustion/server/recovers-after-release", recovered, 30)
        finally:
            for sock in sockets:
                sock.close()
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    async def client_descriptors(self):
        sp, lp = port(), port()
        server = await self.suite.spawn("fd-client-server", "server", f"ws://127.0.0.1:{sp}",
                                        "--restrict-config", str(self.policy))
        sockets = []
        try:
            await self.suite.ready(sp, server)
            client = await self.suite.spawn("fd-client", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}",
                                            "--connection-retry-max-backoff", "2s", f"ws://127.0.0.1:{sp}",
                                            preexec_fn=limit_descriptors(self.args.fd_limit))
            await self.listening(lp, client)
            await self.suite.check("fd-exhaustion/client/baseline", lambda: self.reaches(lp))

            async def exhausted():
                sockets.extend(await asyncio.to_thread(self.flood, (lp,), 3 * self.args.fd_limit))
                details = await self.exhausted("fd-client", client, len(sockets), accept_loops=1)
                return {**details, "flood_connections": len(sockets), "fd_limit": self.args.fd_limit}
            await self.suite.check("fd-exhaustion/client/no-spin-no-log-flood", exhausted, 30)

            async def recovered():
                for sock in sockets:
                    sock.close()
                sockets.clear()
                deadline = time.monotonic() + 15
                while True:
                    try:
                        return await self.reaches(lp)
                    except (OSError, AssertionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                        if time.monotonic() > deadline:
                            raise
                        await asyncio.sleep(0.5)
            await self.suite.check("fd-exhaustion/client/recovers-after-release", recovered, 30)
        finally:
            for sock in sockets:
                sock.close()
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes[-2:]))

    async def configuration(self):
        def run(*args):
            return subprocess.run([str(self.suite.binary), *args], capture_output=True, text=True, timeout=20)

        async def checks():
            zero = run("server", "-t", "--tls-handshake-timeout", "0s", "ws://127.0.0.1:1")
            assert zero.returncode == 1 and "--tls-handshake-timeout must be greater than zero" in zero.stderr, zero.stderr
            no_slots = run("server", "-t", "--max-pending-tls-handshakes", "0", "ws://127.0.0.1:1")
            assert no_slots.returncode == 2, no_slots.stderr
            valid = run("server", "-t", "--tls-handshake-timeout", "3s", "--max-pending-tls-handshakes", "8",
                        "--restrict-config", str(self.policy), "ws://127.0.0.1:1")
            assert valid.returncode == 0, valid.stderr
            help_text = run("server", "--help").stdout
            for flag, default in (("--tls-handshake-timeout", "10s"), ("--max-pending-tls-handshakes", "1024")):
                assert flag in help_text and f"[default: {default}]" in help_text, f"{flag} missing from help"
            return {"zero_timeout_exit": zero.returncode, "zero_slots_exit": no_slots.returncode, "valid_exit": valid.returncode}
        await self.suite.check("config/handshake-bounds-validated", checks)

    async def run(self):
        sections = self.args.sections.split(",")
        (self.out / "metadata.json").write_text(json.dumps({
            "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
            "platform": platform.platform(), "python": sys.version.split()[0], "sections": sections,
            "fd_limit": self.args.fd_limit, "quic_client": self.quic_client_version(),
            "scope": "loopback-only synthetic CA and DNS responder; no external network, firewall changes, or privileges"},
            indent=2))
        try:
            await self.prepare()
            if "cidr" in sections:
                await self.suite.check("cidr/suite", self.cidr, 240)
                await self.suite.check("compat/suite", self.restrict_to_hostname, 40)
                await self.suite.check("dns-rebinding/suite", self.rebinding, 40)
            if "handshake" in sections:
                await self.suite.check("handshake/timeout-suite", self.handshake_timeout, 40)
                await self.suite.check("handshake/limit-suite", self.pending_limit, 60)
                await self.suite.check("handshake/quic-suite", self.quic_bounds, 120)
            if "fd" in sections:
                await self.suite.check("fd-exhaustion/server-suite", self.server_descriptors, 120)
                await self.suite.check("fd-exhaustion/client-suite", self.client_descriptors, 120)
            if "config" in sections:
                await self.configuration()
        finally:
            for writer in self.suite.owned_writers.copy():
                await close(writer)
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            for server in self.servers:
                server.close()
            for transport in self.datagram_transports:
                transport.close()
        failures = sum(row["status"] == "fail" for row in self.suite.results)
        print(f"Artifacts: {self.out}; failed checks: {failures}", flush=True)
        return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    parser.add_argument("--sections", default="cidr,handshake,fd,config")
    parser.add_argument("--fd-limit", type=int, default=64)
    parser.add_argument("--openssl", default="openssl",
                        help="OpenSSL CLI whose s_client drives the WebTransport checks; needs 3.5+ for -quic")
    parser.add_argument("--require-quic", action="store_true",
                        help="fail, instead of skipping, the WebTransport checks when --openssl lacks QUIC")
    args = parser.parse_args()
    if any(s not in ("cidr", "handshake", "fd", "config") for s in args.sections.split(",")):
        parser.error("unsupported section")
    if not 32 <= args.fd_limit <= 1024:
        parser.error("--fd-limit must be within 32..1024")
    raise SystemExit(int(asyncio.run(Hardening(args).run())))


if __name__ == "__main__":
    main()
