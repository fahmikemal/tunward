#!/usr/bin/env python3
"""Bounded loopback mTLS quota checks; no external targets or deployed device identities."""

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import time

from qualify import EchoUDP, Suite, close, port
from qualify_wan import certificates, command


class QuotaChecks:
    def __init__(self, args):
        self.suite = Suite(args)
        self.suite.out.chmod(0o700)
        self.certs = self.suite.out / "certificates"
        self.accepted = 0
        self.serial = 0

    async def echo(self, reader, writer):
        self.accepted += 1
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            await close(writer)

    async def prepare(self):
        await certificates(self.certs, "127.0.0.1")
        for serial, (name, identity) in enumerate(
                (("a", "device-a"), ("b", "device-b"), ("rotated-a", "device-a")), 301):
            await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                          "-subj", f"/CN={identity}", "-keyout", self.certs / f"{name}.key",
                          "-out", self.certs / f"{name}.csr")
            await command("openssl", "x509", "-req", "-in", self.certs / f"{name}.csr", "-CA", self.certs / "ca.pem",
                          "-CAkey", self.certs / "ca.key", "-set_serial", serial, "-days", 4,
                          "-extfile", self.certs / "client.ext", "-out", self.certs / f"{name}.pem")
            (self.certs / f"{name}.key").chmod(0o600)
        self.target = await asyncio.start_server(self.echo, "127.0.0.1", 0)
        self.target_port = self.target.sockets[0].getsockname()[1]
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoUDP, local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp.get_extra_info("sockname")[1]
        self.unused_port = port()
        self.suite.echo_port = self.target_port
        self.policy = self.suite.out / "restrictions.yaml"
        self.policy.write_text(f"""restrictions:
  - name: Synthetic quota identities
    match:
      - !PathPrefix '^device-[ab]$'
    allow:
      - !Tunnel
        protocol: [Tcp, Udp]
        port: ["{self.target_port}", "{self.udp_port}", "{self.unused_port}"]
        cidr: [127.0.0.1/32]
      - !ReverseTunnel
        protocol: [Tcp, Udp, Socks5, HttpProxy, Unix]
        cidr: [127.0.0.1/32]
""")

    @asynccontextmanager
    async def server(self, label, limits, extra=""):
        self.serial += 1
        prefix = f"{self.serial}-{label}"
        config = self.suite.out / f"{prefix}-quotas.yaml"
        config.write_text("version: 1\ndefault:\n" + "".join(f"  {key}: {value}\n" for key, value in limits.items()) + extra)
        sp, mp = port(), port()
        process = await self.suite.spawn(prefix, "server", f"wts://127.0.0.1:{sp}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(self.policy),
            "--device-quota-config", str(config), "--management-api", f"127.0.0.1:{mp}",
            "--remote-to-local-server-idle-timeout", "3s", "--websocket-ping-frequency", "1s")
        clients, writers = [], []
        await self.suite.ready(sp, process)
        try:
            yield {"port": sp, "management": mp, "prefix": prefix, "clients": clients, "writers": writers}
        finally:
            await asyncio.gather(*(close(writer) for writer in writers))
            await asyncio.gather(*(self.suite.stop(client) for client in clients))
            await self.suite.stop(process)

    async def passive_listener(self, endpoint, process):
        # Connecting here would itself consume tunnel/request quota.
        for _ in range(400):
            lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
            if any(int(row.split()[1].rsplit(":", 1)[1], 16) == endpoint and row.split()[3] == "0A" for row in lines):
                return
            if process.returncode is not None:
                raise RuntimeError("client exited before listening")
            await asyncio.sleep(0.01)
        raise TimeoutError("client listener unavailable")

    async def client(self, stack, scheme, identity="a", label="spoofed-label", specs=None, extra_args=()):
        endpoint = port()
        if specs is None:
            specs = ["-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{self.target_port}"]
        process = await self.suite.spawn(f'{stack["prefix"]}-client-{len(stack["clients"])}', "client", *specs,
            "--tls-verify-certificate", "--tls-certificate", str(self.certs / f"{identity}.pem"),
            "--tls-private-key", str(self.certs / f"{identity}.key"),
            "--client-id", label, "--connection-retry-max-backoff", "1s",
            "--websocket-ping-frequency", "1s",
            "--reverse-tunnel-connection-retry-max-backoff", "1s", *extra_args, f'{scheme}://127.0.0.1:{stack["port"]}',
            extra_env={"SSL_CERT_FILE": str(self.certs / "ca.pem"), "SSL_CERT_DIR": ""})
        stack["clients"].append(process)
        if specs[0] == "-L":
            listener = int(specs[1].split("127.0.0.1:", 1)[1].split(":", 1)[0])
            await self.passive_listener(listener, process)
        return endpoint, process

    async def held(self, stack, endpoint, size=16):
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        stack["writers"].append(writer)
        data = os.urandom(size)
        writer.write(data)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(size), 10) == data
        return writer

    async def denied(self, stack, endpoint):
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        stack["writers"].append(writer)
        try:
            writer.write(b"denied")
            await writer.drain()
            received = await asyncio.wait_for(reader.read(6), 3)
            assert received == b"", received
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            await close(writer)

    def log(self, stack):
        return (self.suite.out / f'{stack["prefix"]}.log').read_text()

    def context(self, identity):
        context = ssl.create_default_context(cafile=self.certs / "ca.pem")
        context.load_cert_chain(self.certs / f"{identity}.pem", self.certs / f"{identity}.key")
        return context

    async def raw_http(self, stack, identity):
        reader, writer = await asyncio.open_connection("127.0.0.1", stack["port"], ssl=self.context(identity))
        try:
            writer.write(b"GET /device-a/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 3)
            header = response.split(b"\r\n\r\n", 1)[0].lower()
            return int(header.split()[1]), header
        finally:
            await close(writer)

    async def tunnels(self):
        async with self.server("tunnels", {"max_sessions": 32, "max_tunnels": 2}) as stack:
            endpoints = {}
            for scheme in ("wss", "https", "wts"):
                endpoints[scheme], _ = await self.client(stack, scheme, label=f"forged-{scheme}")
            first = await self.held(stack, endpoints["wss"])
            second = await self.held(stack, endpoints["https"])
            before = self.accepted
            await asyncio.gather(*(self.denied(stack, endpoints["wts"]) for _ in range(16)))
            assert self.accepted == before, "rejected tunnels reached the target"
            assert "tunnel_limit" in self.log(stack)
            b, _ = await self.client(stack, "wts", "b", "forged-wss")
            await self.held(stack, b)
            await close(first)
            await asyncio.sleep(0.15)
            await self.held(stack, endpoints["wts"])
            await close(second)
            return {"shared_transports": ["wss", "https", "wts"], "concurrent_rejections": 16,
                    "separate_device_allowed": True, "labels_do_not_change_identity": True}

    async def failed_setup(self):
        async with self.server("failed-setup", {"max_tunnels": 1}) as stack:
            failed_port = port()
            specs = ["-L", f"tcp://127.0.0.1:{failed_port}:127.0.0.1:{self.unused_port}"]
            await self.client(stack, "wss", specs=specs)
            await self.denied(stack, failed_port)
            for scheme in ("wss", "https", "wts"):
                endpoint, process = await self.client(stack, scheme)
                writer = await self.held(stack, endpoint)
                await close(writer)
                await self.suite.stop(process)
                await asyncio.sleep(0.1)
            return {"failed_target_releases_slot": True, "close_and_abort_recover": True}

    async def sessions(self):
        async with self.server("sessions", {"max_sessions": 2, "max_tunnels": 8}) as stack:
            for _ in range(2):
                _, writer = await asyncio.open_connection("127.0.0.1", stack["port"], ssl=self.context("a"))
                stack["writers"].append(writer)
            await asyncio.sleep(0.1)
            for scheme in ("wss", "https", "wts"):
                endpoint, process = await self.client(stack, scheme)
                await self.denied(stack, endpoint)
                await self.suite.stop(process)
            b, _ = await self.client(stack, "wss", "b")
            await self.held(stack, b)
            assert "session_limit" in self.log(stack)
            await close(stack["writers"][0])
            await asyncio.sleep(0.1)
            a, _ = await self.client(stack, "wts", "rotated-a", "new-label")
            await self.held(stack, a)
            return {"idle_authenticated_tcp_sessions_count": True, "all_transports_share_cap": True,
                    "released_slot_reusable_with_rotated_key": True}

    async def requests(self):
        async with self.server("requests", {"max_sessions": 16, "requests_per_second": 1, "request_burst": 1}) as stack:
            status, _ = await self.raw_http(stack, "a")
            assert status == 400
            status, header = await self.raw_http(stack, "rotated-a")
            assert status == 429 and b"retry-after: 1" in header and b"cache-control: no-store" in header, header
            status, _ = await self.raw_http(stack, "b")
            assert status == 400
            await asyncio.sleep(1.05)
            status, _ = await self.raw_http(stack, "a")
            assert status == 400
            return {"reconnect_and_key_rotation_share_bucket": True, "retry_after": True, "refill_recovers": True}

    async def bandwidth(self, direction):
        async with self.server(f"bandwidth-{direction}", {f"{direction}_bytes_per_second": 65536}) as stack:
            endpoints = [await self.client(stack, scheme) for scheme in ("wss", "https", "wts")]
            before = time.monotonic()
            await asyncio.gather(*(self.held(stack, endpoint, 65536) for endpoint, _ in endpoints))
            elapsed = time.monotonic() - before
            assert elapsed >= 1.8, f"aggregate payload escaped rate limit: {elapsed}"
            return {"payload_bytes": 196608, "initial_burst_bytes": 65536, "rate_bytes_per_second": 65536,
                    "seconds": round(elapsed, 3), "shared_transports": 3}

    async def udp_and_proxies(self):
        async with self.server("protocols", {"max_sessions": 32, "max_tunnels": 16,
                                             "upload_bytes_per_second": 262144, "download_bytes_per_second": 262144}) as stack:
            for scheme in ("wss", "https", "wts"):
                endpoints = {name: port() for name in ("tcp", "socks", "http", "udp")}
                unix = str(self.suite.out / f"{scheme}-quota.sock")
                specs = ["-L", f'tcp://127.0.0.1:{endpoints["tcp"]}:127.0.0.1:{self.target_port}',
                         "-L", f'socks5://127.0.0.1:{endpoints["socks"]}', "-L", f'http://127.0.0.1:{endpoints["http"]}',
                         "-L", f'udp://127.0.0.1:{endpoints["udp"]}:127.0.0.1:{self.udp_port}',
                         "-L", f"unix://{unix}:127.0.0.1:{self.target_port}"]
                _, process = await self.client(stack, scheme, specs=specs)
                for mode in ("tcp", "socks", "http", "unix"):
                    await self.suite.exchange(mode, unix if mode == "unix" else endpoints[mode], 1024)
                await self.suite.udp(endpoints["udp"], 40000, 4)
                await self.suite.stop(process)
            return {"transports": 3, "stream_ingress": ["tcp", "socks", "http", "unix"],
                    "udp_bytes_per_datagram": 40000, "datagram_integrity": True}

    @staticmethod
    def bound(endpoint):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", endpoint))
                return False
            except OSError:
                return True

    async def reverse(self):
        for scheme in ("wss", "https", "wts"):
            async with self.server(f"reverse-{scheme}", {"max_sessions": 8, "max_tunnels": 1}) as stack:
                fixed = port()
                _, reverse = await self.client(stack, scheme, label="reverse-a",
                    specs=["-R", f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"])
                for _ in range(100):
                    if self.bound(fixed):
                        break
                    await asyncio.sleep(0.03)
                else:
                    raise AssertionError("reverse listener not allocated")
                endpoint, _ = await self.client(stack, "wts")
                await self.denied(stack, endpoint)
                await self.suite.stop(reverse)
                for _ in range(200):
                    if not self.bound(fixed):
                        break
                    await asyncio.sleep(0.03)
                else:
                    raise AssertionError(f"{scheme}: cancelled reverse listener or its quota did not release")
                await self.held(stack, endpoint)
        return {"pending_listener_charged": True, "cancelled_listener_freed": True,
                "slot_reusable": True, "transports": ["wss", "https", "wts"],
                "test_quic_idle_timeout_seconds": 3}

    async def reverse_ownership(self):
        async with self.server("reverse-ownership", {"max_sessions": 8, "max_tunnels": 1}) as stack:
            fixed = port()
            spec = ["-R", f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"]
            await self.client(stack, "wss", "a", "same-label", spec)
            for _ in range(100):
                if self.bound(fixed):
                    break
                await asyncio.sleep(0.03)
            else:
                raise AssertionError("owner reverse listener not allocated")
            _, other = await self.client(stack, "wss", "b", "same-label", spec)
            for _ in range(100):
                if any(f"Cannot start TCP server on 127.0.0.1:{fixed}" in line and "/device-b/events" in line
                       for line in self.log(stack).splitlines()):
                    break
                await asyncio.sleep(0.03)
            else:
                raise AssertionError("different verified identity reused another device's listener")
            await self.suite.stop(other)
            endpoint, _ = await self.client(stack, "wts", "b")
            await self.held(stack, endpoint)
            await self.held(stack, fixed)
            return {"cross_identity_listener_reuse_denied": True, "failed_bind_releases_quota": True}

    async def invalid_config(self):
        config = self.suite.out / "invalid.yaml"
        config.write_text("version: 1\ndefault: {max_sessions: 1}\n")
        process = await self.suite.spawn("quota-cleartext-rejected", "server", f"ws://127.0.0.1:{port()}",
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--device-quota-config", str(config))
        assert await asyncio.wait_for(process.wait(), 5) != 0
        log = (self.suite.out / "quota-cleartext-rejected.log").read_text()
        assert "device quotas require TLS" in log
        return {"cleartext_rejected_before_listen": True}

    async def default_resource_limits(self):
        sp, mp = port(), port()
        process = await self.suite.spawn("default-quota-server", "server", f"wts://127.0.0.1:{sp}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(self.policy),
            "--management-api", f"127.0.0.1:{mp}")
        clients = []
        await self.suite.ready(sp, process)
        try:
            lp = port()
            c = await self.suite.spawn("default-quota-client", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.target_port}",
                "-P", "device-a", "--tls-certificate", str(self.certs / "a.pem"), "--tls-private-key", str(self.certs / "a.key"),
                "--tls-verify-certificate=false", f"wts://127.0.0.1:{sp}")
            clients.append(c)
            await self.suite.ready(lp, c)
            r, w = await asyncio.open_connection("127.0.0.1", lp)
            w.write(b"hello-default-quota\n")
            await w.drain()
            data = await r.read(64)
            assert data == b"hello-default-quota\n"
            await close(w)
            return {"default_limits_applied_and_tunnel_succeeds": True}
        finally:
            await asyncio.gather(*(self.suite.stop(c) for c in clients))
            await self.suite.stop(process)

    async def run(self):
        await self.prepare()
        try:
            for name, case in (
                ("tunnels-cross-transport", self.tunnels), ("failed-setup-and-recovery", self.failed_setup),
                ("session-cap-and-rotation", self.sessions), ("request-rate-and-reconnect", self.requests),
                ("aggregate-upload", lambda: self.bandwidth("upload")),
                ("aggregate-download", lambda: self.bandwidth("download")),
                ("udp-and-proxies", self.udp_and_proxies), ("reverse-cancellation", self.reverse),
                ("reverse-resource-ownership", self.reverse_ownership),
                ("default-resource-limits", self.default_resource_limits),
                ("startup-requires-mtls", self.invalid_config),
            ):
                await self.suite.check(f"quotas/{name}", case, 45)
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in self.suite.processes))
            self.target.close()
            await self.target.wait_closed()
            self.udp.close()
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "bounded loopback synthetic mTLS; process-local quotas; no cluster/physical-device claim",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(QuotaChecks(parser.parse_args()).run())))
