#!/usr/bin/env python3
"""Release-binary checks of trust boundaries: forwarded client addresses, server-named reverse
destinations, listeners that cannot bind, and default quotas under --allow-insecure-dev."""
import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
import socket
import struct

from qualify import Suite, close, port
from qualify_wan import certificates

SPOOFED = "203.0.113.9"


class TrustBoundaryChecks:
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

    async def forwarded_for(self):
        """A spoofed X-Forwarded-For reaches the target's PROXY v2 header only through a trusted proxy."""
        sources = asyncio.Queue()

        async def target(reader, writer):
            try:
                head = await reader.readexactly(16)
                assert head[:12] == b"\r\n\r\n\x00\r\nQUIT\n", head
                body = await reader.readexactly(struct.unpack("!H", head[14:16])[0])
                family = socket.AF_INET if head[13] >> 4 == 1 else socket.AF_INET6
                await sources.put(socket.inet_ntop(family, body[:4] if family == socket.AF_INET else body[:16]))
            except asyncio.IncompleteReadError:
                pass
            finally:
                await close(writer)

        server = await asyncio.start_server(target, "127.0.0.1", 0)
        target_port = server.sockets[0].getsockname()[1]
        rules = self.policy("forward", f"      - !Tunnel {{protocol: [Tcp], port: ['{target_port}'], cidr: [127.0.0.1/32]}}\n")
        observed = {}
        try:
            for trusted, expected in ((None, "127.0.0.1"), ("127.0.0.1", SPOOFED)):
                sp = port()
                extra = ["--trusted-proxy", trusted] if trusted else []
                srv = await self.suite.spawn(f"xff-server-{trusted or 'none'}", "server", f"wss://127.0.0.1:{sp}",
                                             *self.server_tls(), "--restrict-config", rules, "--enable-webtransport", *extra)
                await self.suite.ready(sp, srv)
                for scheme in ("wss", "https", "wts"):
                    lp = port()
                    cli = await self.suite.spawn(f"xff-client-{trusted or 'none'}-{scheme}", "client",
                                                 "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{target_port}?proxy_protocol",
                                                 "-H", f"X-Forwarded-For: {SPOOFED}", *self.client_tls(),
                                                 f"{scheme}://127.0.0.1:{sp}", extra_env=self.ca)
                    try:
                        await self.suite.ready(lp, cli)
                        # The readiness probe opens a tunnel too; drop the header it left.
                        await asyncio.sleep(0.5)
                        while not sources.empty():
                            sources.get_nowait()
                        _, writer = await asyncio.open_connection("127.0.0.1", lp)
                        writer.write(b"x")
                        await writer.drain()
                        source = await asyncio.wait_for(sources.get(), 10)
                        await close(writer)
                    finally:
                        await self.suite.stop(cli)
                    observed[f"{scheme}/trusted={trusted or 'none'}"] = source
                    assert source == expected, f"{scheme} trusted={trusted}: PROXY v2 source {source}, expected {expected}"
                await self.suite.stop(srv)
        finally:
            server.close()
        return {"proxy_protocol_sources": observed, "spoofed_address_ignored_without_trusted_proxy": True}

    async def reverse_destination(self):
        """A hostile server naming another destination cannot redirect a fixed reverse tunnel."""
        hits = {"target": 0, "decoy": 0}

        def listener(name):
            async def handle(reader, writer):
                hits[name] += 1
                writer.write(await reader.read(64))
                await writer.drain()
                await close(writer)
            return handle

        target = await asyncio.start_server(listener("target"), "127.0.0.1", 0)
        decoy = await asyncio.start_server(listener("decoy"), "127.0.0.1", 0)
        target_port, decoy_port = (s.sockets[0].getsockname()[1] for s in (target, decoy))
        rules = self.policy("reverse", "      - !ReverseTunnel {protocol: [Tcp], cidr: [127.0.0.1/32]}\n")
        sp, reverse_port = port(), port()
        srv = await self.suite.spawn("reverse-server", "server", f"ws://127.0.0.1:{sp}", "--restrict-config", rules)
        await self.suite.ready(sp, srv)

        async def pump(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                await close(writer)

        async def relay(client_reader, client_writer):
            # Plays a hostile server: relays to the real one and names the decoy in each response.
            try:
                server_reader, server_writer = await asyncio.open_connection("127.0.0.1", sp)
                request = await client_reader.readuntil(b"\r\n\r\n")
                server_writer.write(request)
                await server_writer.drain()
                token = re.search(rb"tunward\.metadata\.v2\.([A-Za-z0-9_-]+)", request)
                asyncio.create_task(pump(client_reader, server_writer))
                response = await server_reader.readuntil(b"\r\n\r\n")
                if token:
                    payload = token[1] + b"=" * (-len(token[1]) % 4)
                    claims = {**json.loads(base64.urlsafe_b64decode(payload)), "r": "127.0.0.1", "rp": decoy_port}
                    cookie = "v2." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
                    response = response.replace(b"\r\n", f"\r\ncookie: {cookie}\r\n".encode(), 1)
                client_writer.write(response)
                await client_writer.drain()
                await pump(server_reader, client_writer)
            except (asyncio.IncompleteReadError, OSError):
                await close(client_writer)

        hostile = await asyncio.start_server(relay, "127.0.0.1", 0)
        hostile_port = hostile.sockets[0].getsockname()[1]
        cli = await self.suite.spawn("reverse-client", "client", "-R",
                                     f"tcp://127.0.0.1:{reverse_port}:127.0.0.1:{target_port}", f"ws://127.0.0.1:{hostile_port}")
        try:
            await self.suite.ready(reverse_port, srv)
            reader, writer = await asyncio.open_connection("127.0.0.1", reverse_port)
            writer.write(b"hello")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.read(64), 10)
            await close(writer)
            await asyncio.sleep(0.5)
        finally:
            await self.suite.stop(cli)
            await self.suite.stop(srv)
            for listening in (hostile, target, decoy):
                listening.close()
        warned = "Ignoring a destination named by the server" in self.log("reverse-client")
        # The readiness probe is a reverse connection too, so the target may count it.
        assert echoed == b"hello" and hits["target"] >= 1 and hits["decoy"] == 0, (echoed, hits)
        assert warned, "the client did not log the ignored destination"
        return {"configured_target_reached": True, "server_named_decoy_reached": False, "client_warned": True}

    async def listener_binds(self):
        """A server asked for WebTransport or the management API does not start without it."""
        rules = self.policy("binds", "      - !Tunnel {port: ['9'], cidr: [127.0.0.1/32]}\n")
        outcomes = {}
        sp = port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
            taken.bind(("127.0.0.1", sp))
            srv = await self.suite.spawn("udp-taken", "server", f"wts://127.0.0.1:{sp}", *self.server_tls(), "--restrict-config", rules)
            outcomes["webtransport_udp_taken_exit"] = await asyncio.wait_for(srv.wait(), 10)
        assert outcomes["webtransport_udp_taken_exit"] != 0 and "Failed to bind to udp socket" in self.log("udp-taken")
        sp, mp = port(), port()
        with socket.socket() as taken:
            taken.bind(("127.0.0.1", mp))
            taken.listen()
            srv = await self.suite.spawn("management-taken", "server", f"wss://127.0.0.1:{sp}", *self.server_tls(),
                                         "--restrict-config", rules, "--management-api", f"127.0.0.1:{mp}")
            outcomes["management_port_taken_exit"] = await asyncio.wait_for(srv.wait(), 10)
        assert outcomes["management_port_taken_exit"] != 0 and "Failed to bind the management API" in self.log("management-taken")
        return outcomes

    async def insecure_dev_quotas(self):
        """--allow-insecure-dev keeps the default 32-session limit; only --no-device-quotas lifts it."""
        held = []

        async def echo(reader, writer):
            held.append(writer)
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass

        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        rules = self.policy("quota", f"      - !Tunnel {{protocol: [Tcp], port: ['{echo_port}'], cidr: [127.0.0.1/32]}}\n")
        established = {}
        try:
            for flag in ("--allow-insecure-dev", "--no-device-quotas"):
                sp, lp = port(), port()
                srv = await self.suite.spawn(f"quota-server{flag}", "server", f"wss://127.0.0.1:{sp}", *self.server_tls(),
                                             "--restrict-config", rules, flag)
                await self.suite.ready(sp, srv)
                cli = await self.suite.spawn(f"quota-client{flag}", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{echo_port}",
                                             *self.client_tls(), f"wss://127.0.0.1:{sp}", extra_env=self.ca)
                await self.suite.ready(lp, cli)

                async def tunnel():
                    reader, writer = await asyncio.open_connection("127.0.0.1", lp)
                    writer.write(b"ping")
                    await writer.drain()
                    try:
                        return await asyncio.wait_for(reader.read(4), 8) == b"ping", writer
                    except (TimeoutError, OSError):
                        return False, writer

                # Each WebSocket tunnel is its own TLS session, so 40 at once exceed the 32-session default.
                outcomes = await asyncio.gather(*(tunnel() for _ in range(40)))
                established[flag] = sum(ok for ok, _ in outcomes)
                for writer in [w for _, w in outcomes] + held:
                    await close(writer)
                held.clear()
                await self.suite.stop(cli)
                await self.suite.stop(srv)
        finally:
            echo_server.close()
        assert 0 < established["--allow-insecure-dev"] <= 32, established
        assert established["--no-device-quotas"] == 40, established
        return {"concurrent_wss_tunnels_established": established}

    async def run(self):
        await certificates(self.certs, "127.0.0.1")
        try:
            for name, check in (("forwarded-for", self.forwarded_for), ("reverse-destination", self.reverse_destination),
                                ("listener-binds", self.listener_binds), ("insecure-dev-quotas", self.insecure_dev_quotas)):
                await self.suite.check(f"trust/{name}", check, 90)
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in self.suite.processes))
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "loopback-only synthetic CA; WSS, HTTP/2 and WebTransport; a hostile server simulated by a cleartext relay",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(TrustBoundaryChecks(parser.parse_args()).run())))
