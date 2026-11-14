#!/usr/bin/env python3
"""Verified-mTLS local soak for existing forward/reverse TCP, SOCKS5 and HTTP proxies."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import time

from qualify import close, port, stats
from qualify_proxy_cleanup import CleanupChecks, open_application


STREAM_MODES = ("forward-tcp", "forward-socks", "forward-http", "reverse-tcp", "reverse-socks", "reverse-http")


def percentiles(values):
    ordered = sorted(values)
    return {name: round(ordered[min(len(ordered) - 1, int(len(ordered) * fraction))], 3)
            for name, fraction in (("p50_ms", .5), ("p95_ms", .95), ("p99_ms", .99))}


class ProxySoak(CleanupChecks):
    async def settled_soak(self, stack, active, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            health = await self.suite.api(stack["management"], "/healthz")
            sessions = await self.sessions(stack)
            if len(self.active(sessions)) == active and health["active_tunnels"] <= active + 3:
                return health
            await asyncio.sleep(.025)
        raise AssertionError(f"soak resources did not settle: {health}; {sessions}")

    async def ordinary_request(self, endpoint, mode):
        data = os.urandom(1024)
        reader, writer = await open_application(mode, endpoint, self.unused_port, len(data))
        try:
            writer.write(data)
            await writer.drain()
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            assert b" 200 " in header.split(b"\r\n", 1)[0], header
            assert await asyncio.wait_for(reader.readexactly(len(data)), 5) == data
            assert await asyncio.wait_for(reader.read(), 5) == b""
        finally:
            await close(writer)

    async def roundtrip(self, mode, reader, writer, payload, timings):
        start = time.monotonic()
        writer.write(payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload
        timings[mode].append((time.monotonic() - start) * 1000)

    async def transient(self, mode, endpoint, timings):
        reader, writer = await open_application(mode, endpoint, self.target_port)
        try:
            await self.roundtrip(mode, reader, writer, os.urandom(65536), timings)
            writer.write_eof()
            assert await asyncio.wait_for(reader.read(), 5) == b""
        finally:
            await close(writer)

    async def one(self, scheme):
        connections = []
        async with self.stack(f"{scheme}-proxy-soak", max_tunnels=64) as stack:
            before_clients = stats(stack["process"].pid)
            endpoints = {mode: port() for mode in STREAM_MODES}
            specs = []
            for mode, endpoint in endpoints.items():
                protocol = "socks5" if mode.endswith("socks") else "http" if mode.endswith("http") else "tcp"
                destination = f":127.0.0.1:{self.target_port}" if protocol == "tcp" else ""
                specs += ["-R" if mode.startswith("reverse") else "-L", f"{protocol}://127.0.0.1:{endpoint}{destination}"]
            _, client = await self.client(stack, scheme, specs=specs, extra_args=("--connection-min-idle", "0"))
            for endpoint in endpoints.values():
                await self.passive_listener(endpoint, client)
            timings = {mode: [] for mode in STREAM_MODES}
            try:
                for mode in STREAM_MODES:
                    for _ in range(self.suite.args.per_mode):
                        reader, writer = await open_application(mode, endpoints[mode], self.target_port)
                        connections.append((mode, reader, writer))
                        await self.roundtrip(mode, reader, writer, os.urandom(16384), timings)
                active = len(connections)

                async def burst(tick):
                    await asyncio.gather(*(self.transient(STREAM_MODES[(tick + i) % len(STREAM_MODES)],
                        endpoints[STREAM_MODES[(tick + i) % len(STREAM_MODES)]], timings) for i in range(8)))
                    await asyncio.gather(self.ordinary_request(endpoints["forward-http"], "forward-request"),
                                         self.ordinary_request(endpoints["reverse-http"], "reverse-request"))
                    await self.settled_soak(stack, active)

                await burst(0)
                await burst(3)
                baseline = {"server": stats(stack["process"].pid), "client": stats(client.pid)}
                start, tick = time.monotonic(), 0
                samples = [{"elapsed_seconds": 0, **baseline}]
                for values in timings.values():
                    values.clear()
                while time.monotonic() - start < self.suite.args.seconds:
                    pause = min(self.suite.args.sample_seconds, self.suite.args.seconds - (time.monotonic() - start))
                    if pause > 0:
                        await asyncio.sleep(pause)
                    await asyncio.gather(*(self.roundtrip(mode, reader, writer, os.urandom(16384), timings)
                                           for mode, reader, writer in connections))
                    if tick % 6 == 0:
                        await burst(tick)
                    current = {"server": stats(stack["process"].pid), "client": stats(client.pid)}
                    for role, sample in current.items():
                        assert sample["fds"] <= baseline[role]["fds"] + 4, (role, baseline, current)
                        assert sample["threads"] <= baseline[role]["threads"] + 2, (role, baseline, current)
                        assert sample["rss_kib"] < 1024 * 1024, (role, current)
                        assert sample["rss_kib"] <= baseline[role]["rss_kib"] + 32768, (role, baseline, current)
                    samples.append({"elapsed_seconds": round(time.monotonic() - start, 3), **current})
                    tick += 1
                    if tick % 12 == 0:
                        self.suite.record(f"soak/{scheme}/progress-{tick}", verified_rounds=tick, latest=samples[-1])
                elapsed = time.monotonic() - start
                after = {"server": stats(stack["process"].pid), "client": stats(client.pid)}
                for _, _, writer in connections:
                    writer.write_eof()
                for _, reader, writer in connections:
                    assert await asyncio.wait_for(reader.read(), 5) == b""
                    await close(writer)
                connections.clear()
                await self.settled_soak(stack, 0)
                details = {"duration_seconds": round(elapsed, 3), "held_tunnels": active, "verified_rounds": tick,
                    "baseline": baseline, "after": after, "samples": samples,
                    "latency": {mode: percentiles(values) for mode, values in timings.items()},
                    "cpu_percent_one_core": {role: round(100 * (after[role]["cpu_seconds"] - baseline[role]["cpu_seconds"]) / elapsed, 3)
                                             for role in baseline},
                    "heartbeat_seconds": 1, "payload_bytes_per_held_exchange": 16384,
                    "transient_burst_connections": 8, "ordinary_http_requests_per_burst": 2}
                await self.suite.stop(stack["process"])
                await stack["start"]()
                details["restart_recovery"] = await self.recovered(endpoints["forward-tcp"])
                await self.suite.stop(client)
                await self.empty(stack, connections=True)
                final = stats(stack["process"].pid)
                assert final["fds"] <= before_clients["fds"] + 4, (before_clients, final)
                details["server_after_client_shutdown"] = final
                return details
            finally:
                for _, _, writer in connections:
                    writer.transport.abort()
                await asyncio.gather(*(close(writer) for _, _, writer in connections), return_exceptions=True)

    async def run(self):
        state, exit_code = "failed", 1
        started = time.time()
        origins = set()
        async def origin(reader, writer):
            task = asyncio.current_task()
            origins.add(task)
            try:
                header = await reader.readuntil(b"\r\n\r\n")
                lengths = [int(x.split(b":", 1)[1]) for x in header.split(b"\r\n") if x.lower().startswith(b"content-length:")]
                assert len(lengths) == 1 and 0 <= lengths[0] <= 65536, header
                data = await reader.readexactly(lengths[0])
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
                await writer.drain()
            finally:
                await close(writer)
                origins.discard(task)
        http = None
        try:
            await self.prepare()
            http = await asyncio.start_server(origin, "127.0.0.1", self.unused_port)
            await asyncio.gather(*(self.suite.check(f"soak/{scheme}/verified-proxies", lambda s=scheme: self.one(s),
                self.suite.args.seconds + 240) for scheme in self.suite.args.transports.split(",")))
            exit_code = int(any(r["status"] != "pass" for r in self.suite.results))
            state = "completed" if exit_code == 0 else "failed"
            return exit_code
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            if http:
                http.close()
                await asyncio.gather(*tuple(origins), return_exceptions=True)
                await http.wait_closed()
            if hasattr(self, "target"):
                self.target.close()
                await self.target.wait_closed()
            if hasattr(self, "udp"):
                self.udp.close()
            results = self.suite.out / "results.json"
            (self.suite.out / "completion.json").write_text(json.dumps({
                "state": state, "exit_code": exit_code, "started_at_unix": started, "finished_at_unix": time.time(),
                "requested_seconds": self.suite.args.seconds,
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "results_sha256": hashlib.sha256(results.read_bytes()).hexdigest() if results.exists() else None,
                "scope": "Linux loopback verified mTLS, 6 stream modes plus ordinary HTTP churn; no WAN/capacity claim"
            }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    parser.add_argument("--transports", default="wss,https,wts")
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--sample-seconds", type=float, default=5)
    parser.add_argument("--per-mode", type=int, default=3)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 7200 or not 1 <= args.sample_seconds <= 30 or not 1 <= args.per_mode <= 3:
        parser.error("seconds: 30..7200; sample-seconds: 1..30; per-mode: 1..3")
    if not args.transports or any(t not in ("wss", "https", "wts") for t in args.transports.split(",")):
        parser.error("supported transports: wss,https,wts")
    if not Path("/proc/net/tcp").exists():
        parser.error("resource checks require Linux /proc")
    raise SystemExit(asyncio.run(ProxySoak(args).run()))


if __name__ == "__main__":
    main()
