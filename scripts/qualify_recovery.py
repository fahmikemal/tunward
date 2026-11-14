#!/usr/bin/env python3
"""Bounded Linux loopback mTLS recovery/resource checks, without firewall changes or WAN claims."""

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time

from qualify import close, port, stats
from qualify_quotas import QuotaChecks


class Relay(asyncio.DatagramProtocol):
    """TCP/UDP relay whose existing paths can be cut without changing the server or client."""

    def __init__(self, target):
        self.target = target
        self.online = True
        self.writers = set()
        self.tasks = set()
        self.client = None

    def connection_made(self, transport):
        self.udp = transport

    def datagram_received(self, data, address):
        if not self.online:
            return
        if address == self.target:
            if self.client:
                self.udp.sendto(data, self.client)
        else:
            self.client = address
            self.udp.sendto(data, self.target)

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream = None
        pumps = []
        try:
            if not self.online:
                return
            remote, upstream = await asyncio.open_connection(*self.target)
            self.writers.update((writer, upstream))
            async def pump(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            pumps = [asyncio.create_task(pump(reader, upstream)), asyncio.create_task(pump(remote, writer))]
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        except OSError:
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            self.writers.discard(writer)
            self.writers.discard(upstream)
            await close(writer)
            if upstream:
                await close(upstream)
            self.tasks.discard(task)

    def cut(self):
        self.online = False
        for writer in tuple(self.writers):
            writer.transport.abort()

    async def shutdown(self):
        self.tcp.close()
        self.udp.close()
        pending = tuple(self.tasks)
        for writer in tuple(self.writers):
            writer.transport.abort()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await self.tcp.wait_closed()

    @classmethod
    async def open(cls, target):
        relay = cls(target)
        endpoint = port()
        relay.tcp = await asyncio.start_server(relay.accept, "127.0.0.1", endpoint)
        try:
            await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: relay, local_addr=("127.0.0.1", endpoint))
        except BaseException:
            relay.tcp.close()
            await relay.tcp.wait_closed()
            raise
        return relay, endpoint


class RecoveryChecks(QuotaChecks):
    @asynccontextmanager
    async def stack(self, label, max_tunnels=1):
        self.serial += 1
        prefix = f"{self.serial}-{label}"
        sp, mp = port(), port()
        quota = self.suite.out / f"{prefix}-quotas.yaml"
        quota.write_text(f"version: 1\ndefault: {{max_sessions: 32, max_tunnels: {max_tunnels}}}\n")
        args = ("server", f"wts://127.0.0.1:{sp}",
                "--tls-certificate", str(self.certs / "server.pem"),
                "--tls-private-key", str(self.certs / "server.key"),
                "--tls-client-ca-certs", str(self.certs / "ca.pem"),
                "--restrict-config", str(self.policy), "--device-quota-config", str(quota),
                "--management-api", f"127.0.0.1:{mp}", "--websocket-ping-frequency", "1s",
                "--remote-to-local-server-idle-timeout", "1s")
        stack = {"port": sp, "management": mp, "prefix": prefix, "clients": [], "writers": []}
        async def start():
            process = await self.suite.spawn(f"{prefix}-server-{len(self.suite.processes)}", *args)
            await self.suite.ready(mp, process)
            stack["process"] = process
            return process
        stack["start"] = start
        try:
            await start()
            yield stack
        finally:
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await asyncio.gather(*(self.suite.stop(client) for client in stack["clients"]))
            await self.suite.stop(stack["process"])

    async def empty(self, stack, connections=False, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            health = await self.suite.api(stack["management"], "/healthz")
            if health["active_tunnels"] == 0 and (not connections or health["active_connections"] == 0):
                sessions = await self.suite.api(stack["management"], "/api/v1/sessions")
                if not sessions:
                    return health
            await asyncio.sleep(.025)
        raise AssertionError(f"resources did not settle: {health}; sessions={sessions if 'sessions' in locals() else None}")

    async def exchange(self, endpoint, abrupt=False, size=1024):
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            payload = os.urandom(size)
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(size), 12) == payload
            if abrupt:
                writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                writer.transport.abort()
            else:
                writer.write_eof()
                assert await asyncio.wait_for(reader.read(), 5) == b""
        finally:
            await close(writer)

    async def recovered(self, endpoint, timeout=25):
        started = time.monotonic()
        attempts = 0
        while time.monotonic() - started < timeout:
            attempts += 1
            try:
                await asyncio.wait_for(self.exchange(endpoint), 12)
                return {"recovery_seconds": round(time.monotonic() - started, 3), "attempts": attempts}
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                await asyncio.sleep(.05)
        raise AssertionError("the running client did not recover")

    async def client_for(self, stack, scheme, target=None, reverse=None):
        endpoint = port()
        spec = ["-R", f"tcp://127.0.0.1:{reverse}:127.0.0.1:{self.target_port}"] if reverse else [
            "-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{target or self.target_port}"]
        _, client = await self.client(stack, scheme, specs=spec, extra_args=("--connection-min-idle", "0"))
        return (reverse or endpoint), client

    async def churn(self, scheme):
        async with self.stack(f"{scheme}-churn") as stack:
            endpoint, client = await self.client_for(stack, scheme)
            for _ in range(10):
                await self.exchange(endpoint)
                await self.empty(stack)
            before = {"server": stats(stack["process"].pid), "client": stats(client.pid)}
            timings, samples = [], []
            for cycle in range(self.suite.args.cycles):
                started = time.monotonic()
                await self.exchange(endpoint, abrupt=bool(cycle % 2))
                await self.empty(stack)
                timings.append((time.monotonic() - started) * 1000)
                if (cycle + 1) % 10 == 0:
                    samples.append({"cycle": cycle + 1, "server": stats(stack["process"].pid),
                                    "client": stats(client.pid)})
            after = {"server": stats(stack["process"].pid), "client": stats(client.pid)}
            for role in before:
                assert after[role]["fds"] <= before[role]["fds"] + 4, (role, before, after)
                assert after[role]["threads"] <= before[role]["threads"] + 2, (role, before, after)
            await self.suite.stop(client)
            await self.empty(stack, connections=True)
            timings.sort()
            return {"cycles": self.suite.args.cycles, "alternating_eof_and_reset": True,
                    "max_tunnels": 1, "before": before, "after": after,
                    "samples": samples,
                    "exchange_and_cleanup_p50_ms": round(timings[len(timings) // 2], 3),
                    "exchange_and_cleanup_p99_ms": round(timings[min(len(timings) - 1, int(len(timings) * .99))], 3)}

    async def unavailable(self, scheme):
        async with self.stack(f"{scheme}-unavailable") as stack:
            endpoint, _ = await self.client_for(stack, scheme, target=self.unused_port)
            for _ in range(10):
                reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                try:
                    writer.write(b"unavailable")
                    await writer.drain()
                    assert await asyncio.wait_for(reader.read(), 12) == b""
                except ConnectionError:
                    pass
                finally:
                    await close(writer)
                await self.empty(stack)
            target = await asyncio.start_server(self.echo, "127.0.0.1", self.unused_port)
            try:
                recovery = await self.recovered(endpoint)
                await self.empty(stack)
                return {"failed_setups": 10, "quota_slot_reused": True, **recovery}
            finally:
                target.close()
                await target.wait_closed()

    async def slow_target(self, scheme):
        tasks, writers = set(), set()
        released = asyncio.Event()
        accepted = asyncio.Queue()
        async def stall(reader, writer):
            tasks.add(asyncio.current_task())
            writers.add(writer)
            accepted.put_nowait(None)
            try:
                await released.wait()
            finally:
                writers.discard(writer)
                tasks.discard(asyncio.current_task())
                await close(writer)
        async with self.stack(f"{scheme}-backpressure") as stack:
            target = await asyncio.start_server(stall, "127.0.0.1", self.unused_port)
            endpoint, _ = await self.client_for(stack, scheme, target=self.unused_port)
            try:
                for _ in range(5):
                    _, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                    async def upload():
                        while True:
                            writer.write(b"x" * 65536)
                            await writer.drain()
                    sending = asyncio.create_task(upload())
                    try:
                        await asyncio.wait_for(accepted.get(), 5)
                        await asyncio.sleep(.15)
                        health = await self.suite.api(stack["management"], "/healthz")
                        assert tasks and not sending.done() and health["active_tunnels"] == 1, health
                        # asyncio abort alone normally sends TCP FIN. Use RST to cancel,
                        # rather than asking the tunnel to drain a legitimate half-close.
                        writer.get_extra_info("socket").setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        writer.transport.abort()
                        await self.empty(stack)
                    finally:
                        sending.cancel()
                        await asyncio.gather(sending, return_exceptions=True)
                        await close(writer)
                return {"blocked_uploads_cancelled": 5, "local_tcp_reset": True, "quota_slot_reused": True}
            finally:
                target.close()
                released.set()
                for writer in tuple(writers):
                    writer.transport.abort()
                await asyncio.gather(*tuple(tasks), return_exceptions=True)
                await target.wait_closed()

    async def outage(self, scheme, restart=False):
        async with self.stack(f"{scheme}-{'restart' if restart else 'outage'}") as stack:
            relay = None
            if not restart:
                relay, remote_port = await Relay.open(("127.0.0.1", stack["port"]))
                original = stack["port"]
                stack["port"] = remote_port
            try:
                endpoint, _ = await self.client_for(stack, scheme)
                await self.exchange(endpoint)
                await self.empty(stack)
                reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                writer.write(b"held")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(4), 12) == b"held"
                if restart:
                    stack["process"].kill()
                    await stack["process"].wait()
                    await stack["start"]()
                else:
                    relay.cut()
                    await asyncio.sleep(4)
                    relay.online = True
                try:
                    assert await asyncio.wait_for(reader.read(1), 12) == b""
                except ConnectionError:
                    pass
                finally:
                    await close(writer)
                recovery = await self.recovered(endpoint)
                await self.empty(stack)
                return {"same_client_process": True, "server_sigkill": restart,
                        "relay_blackout_seconds": None if restart else 4, **recovery}
            finally:
                if relay:
                    stack["port"] = original
                    await relay.shutdown()

    async def reverse(self, scheme):
        async with self.stack(f"{scheme}-reverse", max_tunnels=4) as stack:
            endpoint = port()
            before = stats(stack["process"].pid)
            for _ in range(5):
                _, client = await self.client_for(stack, scheme, reverse=endpoint)
                await self.recovered(endpoint)
                client.kill()
                await client.wait()
                await self.empty(stack, connections=True)
                # An actual bind proves the cached listener released its endpoint.
                listener = await asyncio.start_server(self.echo, "127.0.0.1", endpoint)
                listener.close()
                await listener.wait_closed()
            after = stats(stack["process"].pid)
            assert after["fds"] <= before["fds"] + 4, (before, after)
            return {"client_crashes": 5, "listener_rebound_each_cycle": True, "before": before, "after": after}

    async def silent_tls(self, scheme):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certs / "server.pem", self.certs / "server.key")
        context.load_verify_locations(self.certs / "ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["h2" if scheme == "https" else "http/1.1"])
        tasks, peers = set(), set()
        async def silent(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            peers.add(writer)
            try:
                while await reader.read(65536):
                    pass
            finally:
                peers.discard(writer)
                tasks.discard(task)
                await close(writer)
        server = await asyncio.start_server(silent, "127.0.0.1", 0, ssl=context)
        stack = {"port": server.sockets[0].getsockname()[1], "prefix": f"silent-{scheme}", "clients": [], "writers": []}
        try:
            endpoint, _ = await self.client_for(stack, scheme)
            started = time.monotonic()
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
            try:
                writer.write(b"no-optimistic-success")
                await writer.drain()
                assert await asyncio.wait_for(reader.read(), 13) == b""
            finally:
                await close(writer)
            deadline = time.monotonic() + 2
            while peers and time.monotonic() < deadline:
                await asyncio.sleep(.025)
            assert not peers, "setup timeout left its authenticated peer socket open"
            return {"tls_authenticated": True, "setup_deadline_seconds": 10,
                    "observed_seconds": round(time.monotonic() - started, 3), "peer_socket_released": True}
        finally:
            server.close()
            await asyncio.gather(*(self.suite.stop(p) for p in stack["clients"]))
            pending = tuple(tasks)
            for peer in tuple(peers):
                peer.transport.abort()
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await server.wait_closed()

    async def run(self):
        state, exit_code = "failed", 1
        started = time.time()
        try:
            await self.prepare()
            for scheme in self.suite.args.transports.split(","):
                for name, check in (("churn", self.churn), ("unavailable-target", self.unavailable),
                                    ("backpressure-cancel", self.slow_target), ("relay-outage", self.outage),
                                    ("server-crash", lambda s: self.outage(s, restart=True)),
                                    ("reverse-client-crash", self.reverse)):
                    await self.suite.check(f"recovery/{scheme}/{name}", lambda s=scheme, fn=check: fn(s), 120)
                if scheme != "wts":
                    await self.suite.check(f"recovery/{scheme}/silent-authenticated-peer",
                                           lambda s=scheme: self.silent_tls(s), 25)
            exit_code = int(any(row["status"] == "fail" for row in self.suite.results))
            state = "completed" if exit_code == 0 else "failed"
            return exit_code
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            if hasattr(self, "target"):
                self.target.close()
                await self.target.wait_closed()
            if hasattr(self, "udp"):
                self.udp.close()
            metadata = {"state": state, "exit_code": exit_code, "started_at_unix": started,
                        "finished_at_unix": time.time(), "cycles": self.suite.args.cycles,
                        "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "results_sha256": hashlib.sha256((self.suite.out / "results.json").read_bytes()).hexdigest()
                        if (self.suite.out / "results.json").exists() else None,
                        "scope": "Linux loopback mTLS, controlled relay outages; no WAN/endurance claim"}
            (self.suite.out / "completion.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--transports", default="wss,https,wts")
    args = parser.parse_args()
    if not 10 <= args.cycles <= 1000:
        parser.error("--cycles must be between 10 and 1000")
    if any(s not in ("wss", "https", "wts") for s in args.transports.split(",")):
        parser.error("supported transports: wss,https,wts")
    if not Path("/proc/net/tcp").exists():
        parser.error("these resource checks require Linux /proc")
    raise SystemExit(asyncio.run(RecoveryChecks(args).run()))


if __name__ == "__main__":
    main()
