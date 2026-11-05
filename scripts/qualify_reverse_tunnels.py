#!/usr/bin/env python3
"""Release-binary checks of reverse tunnels: a server-allocated port (port 0) stays with its client
tunnel across requests, reply timeouts, bursts and UDP peers, a fixed port stays open between two
requests of a distant client, an allow= list limits where the server's peers reach through a reverse
SOCKS5 or HTTP proxy tunnel, and the idle timeout a client names cannot abort the server."""
import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import re
import socket
import struct
import uuid

from qualify import Suite, close, port
from qualify_wan import certificates

# A client abandons a reverse request that no visitor answered after this long and sends another.
REPLY_TIMEOUT = 30
SCHEMES = ("wss", "https", "wts")


class ReverseTunnelChecks:
    def __init__(self, args):
        self.suite = Suite(args)
        self.certs = self.suite.out / "certificates"
        self.ca = {"SSL_CERT_FILE": str(self.certs / "ca.pem"), "SSL_CERT_DIR": ""}

    def server_tls(self):
        return ["--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--tls-client-ca-certs", str(self.certs / "ca.pem")]

    def client_tls(self):
        return ["--tls-certificate", str(self.certs / "client.pem"), "--tls-private-key", str(self.certs / "client.key"),
                "--tls-verify-certificate"]

    def policy(self, name, allow):
        path = self.suite.out / f"{name}-restrictions.yaml"
        path.write_text(f"restrictions:\n  - name: {name}\n    match: [Any]\n    allow:\n{allow}")
        return str(path)

    def log(self, label):
        return (self.suite.out / f"{label}.log").read_text(errors="replace")

    @staticmethod
    async def echo_server():
        """A TCP echo target that counts the connections it accepted."""
        accepted = [0]

        async def echo(reader, writer):
            accepted[0] += 1
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                await close(writer)

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1], accepted

    async def server(self, label, rules):
        sp, mp = port(), port()
        process = await self.suite.spawn(f"{label}-server", "server", f"wss://127.0.0.1:{sp}", *self.server_tls(),
                                         "--restrict-config", rules, "--enable-webtransport",
                                         "--management-api", f"127.0.0.1:{mp}", log_level="INFO")
        await self.suite.ready(sp, process)
        return sp, mp, process

    async def client(self, label, sp, scheme, *tunnels):
        return await self.suite.spawn(label, "client", *tunnels, "--client-id", label, *self.client_tls(),
                                      f"{scheme}://127.0.0.1:{sp}", extra_env=self.ca, log_level="INFO")

    async def listener_ports(self, mp, label):
        records = await self.suite.api(mp, "/api/v1/sessions")
        return sorted({r["assigned_port"] for r in records if r["kind"] == "reverse_listener" and r["client_id"] == label})

    async def first_listener(self, mp, label):
        for _ in range(250):
            if ports := await self.listener_ports(mp, label):
                assert len(ports) == 1, f"{label} opened several listeners: {ports}"
                return ports[0]
            await asyncio.sleep(0.02)
        raise AssertionError(f"{label}: the server opened no reverse listener")

    @staticmethod
    async def echoed(endpoint, payload, timeout=10):
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.readexactly(len(payload)), timeout) == payload
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return False
        finally:
            await close(writer)

    async def allocated_port(self):
        """A port-0 TCP tunnel keeps the port the server allocated on every transport: past a reply
        timeout with no visitor, across sequential visitors, and for a burst that outruns one request."""
        echo, echo_port, _ = await self.echo_server()
        rules = self.policy("allocated", "      - !ReverseTunnel {protocol: [Tcp], cidr: [127.0.0.1/32]}\n")
        sp, mp, srv = await self.server("allocated", rules)
        clients = {}
        try:
            for scheme in SCHEMES:
                label = f"allocated-{scheme}"
                clients[scheme] = await self.client(label, sp, scheme, "-R", f"tcp://127.0.0.1:0:127.0.0.1:{echo_port}")
            first = {scheme: await self.first_listener(mp, f"allocated-{scheme}") for scheme in SCHEMES}
            # No visitor yet: each client gives up on its request and sends another one meanwhile.
            await asyncio.sleep(REPLY_TIMEOUT + 5)
            observed = {}
            for scheme in SCHEMES:
                label, listener = f"allocated-{scheme}", first[scheme]
                ports = await self.listener_ports(mp, label)
                assert ports == [listener], f"{scheme}: the listener moved from {listener} to {ports} before its first visitor"
                for visit in range(10):
                    assert await self.echoed(listener, f"{scheme}-{visit}".encode()), f"{scheme}: visitor {visit} was not served"
                # More visitors at once than one request takes: they wait for the tunnel's next requests.
                burst = await asyncio.gather(*(self.echoed(listener, f"{scheme}-burst-{n}".encode() * 64) for n in range(12)))
                assert all(burst), f"{scheme}: {burst.count(False)} of 12 concurrent visitors were not served"
                assert await self.listener_ports(mp, label) == [listener], f"{scheme}: the listener moved"
                log = self.log(label)
                reported = {int(p) for p in re.findall(r"Reverse tunnel served on server port (\d+)", log)}
                assert reported == {listener}, f"{scheme}: the client reported server ports {reported}, not {listener}"
                assert "moved from server port" not in log, f"{scheme}: the client saw its port move"
                observed[scheme] = {"port": listener, "visitors": 10 + len(burst)}
            allocations = len(re.findall(r"Allocated reverse listener", self.log("allocated-server")))
            assert allocations == len(SCHEMES), f"the server allocated {allocations} listeners for {len(SCHEMES)} tunnels"
            return {"transports": observed, "waited_past_reply_timeout_seconds": REPLY_TIMEOUT + 5,
                    "one_allocation_per_client_tunnel": True}
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in clients.values()))
            await self.suite.stop(srv)
            echo.close()

    @staticmethod
    async def delayed_relay(upstream, delay):
        """A TCP relay to `upstream` that holds every chunk for `delay` seconds in each direction, so a
        client connecting through it is a round trip of twice that away from the server."""
        loop = asyncio.get_running_loop()

        async def pipe(reader, writer):
            queue = asyncio.Queue()

            async def pace():
                try:
                    while (item := await queue.get()) is not None:
                        due, data = item
                        await asyncio.sleep(max(0.0, due - loop.time()))
                        writer.write(data)
                        await writer.drain()
                except OSError:
                    pass
                finally:
                    await close(writer)

            pacer = asyncio.create_task(pace())
            try:
                while data := await reader.read(65536):
                    queue.put_nowait((loop.time() + delay, data))
            except OSError:
                pass
            finally:
                queue.put_nowait(None)
                await pacer

        async def relay(reader, writer):
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", upstream)
            except OSError:
                await close(writer)
                return
            await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))

        server = await asyncio.start_server(relay, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def fixed_port(self):
        """A fixed-port reverse TCP listener stays open between two requests of its tunnel when the
        client is a round trip of 100 ms away, so visitors arriving meanwhile are served. Under the
        default mTLS quotas the server checks such a listener every second; a check that fell into
        that round trip closed it and refused or dropped the visitors until the next request."""
        echo, echo_port, _ = await self.echo_server()
        rules = self.policy("fixed", "      - !ReverseTunnel {protocol: [Tcp], cidr: [127.0.0.1/32]}\n")
        sp, _, srv = await self.server("fixed", rules)
        relay, relay_port = await self.delayed_relay(sp, 0.05)
        pace = random.Random(7)
        outcomes = {}
        try:
            for scheme in ("wss", "https"):
                fixed = port()
                label = f"fixed-{scheme}"
                cli = await self.client(label, relay_port, scheme, "-R", f"tcp://127.0.0.1:{fixed}:127.0.0.1:{echo_port}")
                try:
                    await self.suite.ready(fixed, cli)
                    served = []

                    async def visitor(worker):
                        for visit in range(15):
                            await asyncio.sleep(pace.uniform(0, 0.3))
                            try:
                                served.append(await self.echoed(fixed, f"{scheme}-{worker}-{visit}".encode()))
                            except ConnectionRefusedError:
                                served.append(False)

                    await asyncio.gather(*(visitor(worker) for worker in range(4)))
                    closed = self.log("fixed-server").count(f"reverse tunnel server on 127.0.0.1:{fixed}.")
                    assert all(served) and not closed, (
                        f"{scheme}: {served.count(False)} of {len(served)} visitors not served, "
                        f"the listener closed {closed} times while its client kept asking")
                    outcomes[scheme] = {"port": fixed, "visitors": len(served)}
                finally:
                    await self.suite.stop(cli)
            return {"client_round_trip_ms": 100, "transports": outcomes, "listener_closures": 0}
        finally:
            await self.suite.stop(srv)
            relay.close()
            echo.close()

    async def allocated_udp(self):
        """A port-0 UDP tunnel serves a second peer on the same port after the first one."""
        loop = asyncio.get_running_loop()

        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.transport.sendto(data, addr)

        transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        udp_echo = transport.get_extra_info("sockname")[1]
        rules = self.policy("udp", "      - !ReverseTunnel {protocol: [Udp], cidr: [127.0.0.1/32]}\n")
        sp, mp, srv = await self.server("udp", rules)
        served = {}
        try:
            for scheme in SCHEMES:
                label = f"udp-{scheme}"
                cli = await self.client(label, sp, scheme, "-R", f"udp://127.0.0.1:0:127.0.0.1:{udp_echo}")
                try:
                    listener = await self.first_listener(mp, label)
                    for peer in range(3):
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                            sock.setblocking(False)
                            sock.connect(("127.0.0.1", listener))
                            payload = f"{scheme}-peer-{peer}".encode()
                            await loop.sock_sendall(sock, payload)
                            reply = await asyncio.wait_for(loop.sock_recv(sock, 65535), 5)
                            assert reply == payload, f"{scheme}: peer {peer} got {reply!r}"
                    assert await self.listener_ports(mp, label) == [listener], f"{scheme}: the listener moved"
                    served[scheme] = {"port": listener, "peers": 3}
                finally:
                    await self.suite.stop(cli)
            return {"transports": served}
        finally:
            await self.suite.stop(srv)
            transport.close()

    @staticmethod
    async def socks(endpoint, host, target, payload):
        """Whether `payload` comes back through a SOCKS5 CONNECT to host:target."""
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x00", "SOCKS negotiation failed"
            try:
                ip = ipaddress.ip_address(host)
                address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
            except ValueError:
                address = b"\x03" + bytes([len(host)]) + host.encode()
            writer.write(b"\x05\x01\x00" + address + struct.pack("!H", target))
            await writer.drain()
            head = await reader.readexactly(4)
            if head[1] != 0:
                return False
            await reader.readexactly({1: 4, 4: 16}.get(head[3]) or (await reader.readexactly(1))[0])
            await reader.readexactly(2)
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return False
        finally:
            await close(writer)

    @staticmethod
    async def http_connect(endpoint, host, target, payload):
        """Whether `payload` comes back through an HTTP CONNECT to host:target."""
        authority = f"[{host}]:{target}" if ":" in host else f"{host}:{target}"
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            if b" 200 " not in head.split(b"\r\n")[0]:
                return False
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return False
        finally:
            await close(writer)

    async def allow_list(self):
        """allow= lets the server's SOCKS5 and HTTP proxy peers reach only the listed destinations, on
        every transport, for literal, domain and IPv4-mapped addresses, and the target never sees the
        others."""
        allowed_srv, allowed, _ = await self.echo_server()
        denied_srv, denied, denied_hits = await self.echo_server()
        rules = self.policy("allow", "      - !ReverseTunnel {protocol: [Socks5, HttpProxy], cidr: [127.0.0.1/32]}\n")
        sp, _, srv = await self.server("allow", rules)
        mapped = "::ffff:127.0.0.1"
        outcomes = {}
        try:
            for scheme in SCHEMES:
                socks, http = port(), port()
                spec = f"allow=127.0.0.1:{allowed}"
                label = f"allow-{scheme}"
                cli = await self.client(label, sp, scheme, "-R", f"socks5://127.0.0.1:{socks}?{spec}",
                                        "-R", f"http://127.0.0.1:{http}?{spec}")
                try:
                    await self.suite.ready(socks, cli)
                    await self.suite.ready(http, cli)
                    got = {
                        "socks_ip_allowed": await self.socks(socks, "127.0.0.1", allowed, b"a" * 512),
                        "socks_domain_allowed": await self.socks(socks, "localhost", allowed, b"b" * 512),
                        "socks_mapped_allowed": await self.socks(socks, mapped, allowed, b"c" * 512),
                        "http_allowed": await self.http_connect(http, "127.0.0.1", allowed, b"d" * 512),
                        "http_mapped_allowed": await self.http_connect(http, mapped, allowed, b"i" * 512),
                        "socks_ip_denied": await self.socks(socks, "127.0.0.1", denied, b"e" * 512),
                        "socks_domain_denied": await self.socks(socks, "localhost", denied, b"f" * 512),
                        "socks_mapped_denied": await self.socks(socks, mapped, denied, b"g" * 512),
                        "http_denied": await self.http_connect(http, "127.0.0.1", denied, b"h" * 512),
                        "http_mapped_denied": await self.http_connect(http, mapped, denied, b"j" * 512),
                    }
                    wrong = {name: ok for name, ok in got.items() if ok != name.endswith("_allowed")}
                    assert not wrong, f"{scheme}: unexpected outcomes {wrong}"
                    assert "outside the allow list" in self.log(label), f"{scheme}: the client did not log its refusals"
                    outcomes[scheme] = got
                finally:
                    await self.suite.stop(cli)
            assert denied_hits[0] == 0, f"the denied target accepted {denied_hits[0]} connections"

            # Without allow= the client warns how far the server's peers reach.
            open_socks = port()
            cli = await self.client("allow-none", sp, "wss", "-R", f"socks5://127.0.0.1:{open_socks}")
            try:
                await self.suite.ready(open_socks, cli)
                assert "has no allow= list" in self.log("allow-none"), "no warning for an unlimited reverse proxy"
            finally:
                await self.suite.stop(cli)
            return {"transports": outcomes, "denied_target_connections": denied_hits[0],
                    "warns_without_allow_list": True}
        finally:
            await self.suite.stop(srv)
            allowed_srv.close()
            denied_srv.close()

    async def allow_refused(self):
        """allow= is refused where it cannot apply, before anything starts."""
        refused = {}
        for spec in ("-R tcp://127.0.0.1:1212:127.0.0.1:22?allow=10.0.0.0/8",
                     "-L socks5://127.0.0.1:1212?allow=10.0.0.0/8",
                     "-R socks5://127.0.0.1:1212?allow=2001:db8::1"):
            flag, value = spec.split(" ", 1)
            process = await asyncio.create_subprocess_exec(
                str(self.suite.binary), "client", flag, value, "wss://127.0.0.1:1",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                _, stderr = await asyncio.wait_for(process.communicate(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()
                raise AssertionError(f"{spec} was accepted and the client started")
            assert process.returncode != 0 and b"allow" in stderr, f"{spec}: exit {process.returncode} {stderr[-300:]!r}"
            refused[spec] = process.returncode
        return {"exit_codes": refused}

    @staticmethod
    async def visit_reverse_udp(listener):
        """Keeps sending a datagram until the listener, which opens with the request, serves it."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as visitor:
            while True:
                visitor.sendto(b"visit", ("127.0.0.1", listener))
                await asyncio.sleep(0.05)

    @staticmethod
    async def visit_socks5_relay(listener):
        """Opens a SOCKS5 UDP association on the listener and keeps sending through its relay."""
        while True:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", listener)
                break
            except OSError:
                await asyncio.sleep(0.05)
        try:
            writer.write(b"\x05\x01\x00")
            await reader.readexactly(2)
            writer.write(b"\x05\x03\x00\x01" + bytes(6))
            relay = struct.unpack(">H", (await reader.readexactly(10))[8:])[0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as visitor:
                datagram = b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35visit"
                while True:
                    visitor.sendto(datagram, ("127.0.0.1", relay))
                    await asyncio.sleep(0.05)
        finally:
            await close(writer)

    async def client_chosen_timeouts(self):
        """A reverse request naming a zero or far-future idle timeout, which no tunward client sends,
        is served by the two UDP paths that arm a timer from it, and the server keeps running."""
        rules = self.policy("timeouts", "      - !ReverseTunnel {protocol: [Udp, Socks5], cidr: [127.0.0.1/32]}\n")
        sp = port()
        process = await self.suite.spawn("timeouts-server", "server", f"ws://127.0.0.1:{sp}",
                                         "--restrict-config", rules, log_level="INFO")
        await self.suite.ready(sp, process)
        served = {}
        try:
            for name, timeout in (("zero", {"secs": 0, "nanos": 0}), ("far-future", {"secs": 2**64 - 1, "nanos": 0})):
                for kind, protocol, visit in (
                        ("udp", {"ReverseUdp": {"timeout": timeout}}, self.visit_reverse_udp),
                        ("socks5", {"ReverseSocks5": {"timeout": timeout, "credentials": None}}, self.visit_socks5_relay)):
                    listener = port()
                    claims = {"v": 2, "id": str(uuid.uuid4()), "p": protocol, "r": "127.0.0.1", "rp": listener}
                    envelope = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
                    reader, writer = await asyncio.open_connection("127.0.0.1", sp)
                    visitor = asyncio.create_task(visit(listener))
                    try:
                        writer.write((f"GET /v1/events HTTP/1.1\r\nHost: 127.0.0.1:{sp}\r\nUpgrade: websocket\r\n"
                                      "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                      f"Sec-WebSocket-Protocol: v1, tunward.metadata.v2.{envelope}\r\n\r\n").encode())
                        await writer.drain()
                        # The server answers a reverse request once a visitor arrived and its flow opened.
                        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
                    finally:
                        visitor.cancel()
                        await close(writer)
                    assert head.startswith(b"HTTP/1.1 101"), f"{kind} with a {name} timeout: {head[:80]!r}"
                    served[f"{kind}-{name}"] = 101
            await asyncio.sleep(0.2)
            assert process.returncode is None, f"the server exited with {process.returncode}"
            return {"served": served}
        finally:
            await self.suite.stop(process)

    async def run(self):
        await certificates(self.certs, "127.0.0.1")
        try:
            for name, check, timeout in (("allocated-port", self.allocated_port, 180), ("allocated-udp", self.allocated_udp, 60),
                                         ("fixed-port", self.fixed_port, 120),
                                         ("allow-list", self.allow_list, 120), ("allow-refused", self.allow_refused, 30),
                                         ("client-chosen-timeouts", self.client_chosen_timeouts, 60)):
                await self.suite.check(f"reverse/{name}", check, timeout)
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in self.suite.processes))
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "loopback-only synthetic CA; WSS, HTTP/2 and WebTransport; default device quotas under mTLS",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(ReverseTunnelChecks(parser.parse_args()).run())))
