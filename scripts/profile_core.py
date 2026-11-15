#!/usr/bin/env python3
"""Bounded Linux loopback mTLS performance measurements of existing tunnel modes.

These are observations on a shared host, not capacity ceilings or production SLOs.
Bulk echo goodput counts application bytes in ONE direction; the reply carries
the same bytes. Bulk roundtrip includes transfer/queueing time, not pure RTT.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import time

from qualify import Suite, stats
from qualify_quotas import QuotaChecks
from qualify_runtime import RuntimeChecks, close, port


MODES = ("forward-tcp", "forward-socks", "forward-http", "reverse-tcp", "reverse-socks", "reverse-http",
         "forward-udp", "reverse-udp")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def percentiles(values):
    values = sorted(values)
    return {f"p{p}_ms": round(values[max(0, math.ceil(len(values) * p / 100) - 1)], 4) for p in (50, 95, 99)} if values else {}


def cgroup_cpu():
    return dict((key, int(value)) for key, value in
                (line.split() for line in Path("/sys/fs/cgroup/cpu.stat").read_text().splitlines()))


class CoreProfile(RuntimeChecks):
    def __init__(self, args):
        super().__init__(args)
        self.owned_writers = set()
        self.tasks, self.writers = set(), set()
        self.started = time.time()
        self.serial = 0
        self.source_hashes = {file: digest(Path(__file__).with_name(file)) for file in
                              ("profile_core.py", "qualify_runtime.py", "qualify.py", "qualify_quotas.py", "qualify_wan.py")}

    def record(self, name, status="pass", **details):
        super().record(name, status, **details)
        print(json.dumps(self.results[-1]), flush=True)

    async def spawn(self, label, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TUNWARD_") and k not in
               ("NO_COLOR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "RUST_LOG", "TOKIO_WORKER_THREADS")}
        env.update(NO_COLOR="true", SSL_CERT_FILE=str(self.certs / "ca.pem"), SSL_CERT_DIR="")
        with (self.out / f"{label}.log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(str(self.binary), *map(str, args),
                "--nb-worker-threads", str(self.args.workers), "--log-lvl", "WARN", stdout=log, stderr=log, env=env)
        self.processes.append(process)
        self.process_logs[process.pid] = f"{label}.log"
        return process

    async def stop(self, process):
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

    async def setup(self):
        await self.prepare()
        async def echo(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            self.writers.add(writer)
            try:
                while data := await reader.read(262144):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                await close(writer)
                self.tasks.discard(task)
                self.writers.discard(writer)
        self.target = await asyncio.start_server(echo, "127.0.0.1", 0, backlog=1024)
        self.target_port = self.echo_port = self.target.sockets[0].getsockname()[1]
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, peer):
                self.transport.sendto(data, peer)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp.get_extra_info("sockname")[1]
        self.policy = self.out / "restrictions.yaml"
        self.policy.write_text("restrictions:\n - name: local-profile\n   match: [Any]\n   allow:\n"
            "    - !Tunnel\n      protocol: [Tcp, Udp]\n      cidr: [127.0.0.1/32]\n"
            "    - !ReverseTunnel\n      protocol: [Tcp, Udp, Socks5, HttpProxy]\n      cidr: [127.0.0.1/32]\n")

    @asynccontextmanager
    async def stack(self, scheme):
        self.serial += 1
        server_port, management = port(), port()
        quota = ("--no-device-quotas",) if self.args.quotas == "off" else ()
        server = await self.spawn(f"{self.serial}-{scheme}-server", "server",
            "--tls-certificate", self.certs / "server.pem", "--tls-private-key", self.certs / "server.key",
            "--tls-client-ca-certs", self.certs / "ca.pem", "--restrict-config", self.policy,
            "--management-api", f"127.0.0.1:{management}", "--websocket-ping-frequency", "1s",
            "--remote-to-local-server-idle-timeout", "3s", *quota, f"wts://127.0.0.1:{server_port}")
        client = None
        try:
            await self.ready(management, server)
            endpoints = {mode: port() for mode in self.args.modes}
            options = []
            for mode, endpoint in endpoints.items():
                protocol = "socks5" if mode.endswith("socks") else "http" if mode.endswith("http") else "udp" if mode.endswith("udp") else "tcp"
                destination = f":127.0.0.1:{self.udp_port if protocol == 'udp' else self.target_port}" if protocol in ("tcp", "udp") else ""
                options += ["-R" if mode.startswith("reverse") else "-L", f"{protocol}://127.0.0.1:{endpoint}{destination}"]
            client = await self.spawn(f"{self.serial}-{scheme}-client", "client", "--tls-verify-certificate",
                "--tls-certificate", self.certs / "client.pem", "--tls-private-key", self.certs / "client.key",
                "--connection-min-idle", "0", "--connection-retry-max-backoff", "1s",
                "--reverse-tunnel-connection-retry-max-backoff", "1s", "--websocket-ping-frequency", "1s",
                *options, f"{scheme}://127.0.0.1:{server_port}")
            for mode, endpoint in endpoints.items():
                if not mode.endswith("udp"):
                    await QuotaChecks.passive_listener(self, endpoint, client)
                else:
                    for _ in range(400):
                        if client.returncode is not None:
                            raise RuntimeError("client exited before UDP listener became ready")
                        rows = [line for file in ("/proc/net/udp", "/proc/net/udp6")
                                for line in Path(file).read_text().splitlines()[1:]]
                        if any(int(row.split()[1].rsplit(":", 1)[1], 16) == endpoint for row in rows):
                            break
                        await asyncio.sleep(.01)
                    else:
                        raise TimeoutError("UDP listener unavailable")
            yield endpoints, {"server": server.pid, "client": client.pid, "harness": os.getpid()}
        finally:
            if client:
                await self.stop(client)
            await self.stop(server)

    async def measure(self, name, endpoint, mode, count, roles):
        connections, sockets, timings, setup = [], [], [], []
        datagram = mode.endswith("udp")
        size = self.args.datagram_bytes if datagram else self.args.payload_bytes
        payloads = [os.urandom(size) for _ in range(count)]
        loop = asyncio.get_running_loop()
        async def connect(index):
            started = time.monotonic()
            if datagram:
                sock = socket.socket(type=socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect(("127.0.0.1", endpoint))
                sockets.append(sock)
                await loop.sock_sendall(sock, payloads[index])
                assert await asyncio.wait_for(loop.sock_recv(sock, 65535), 5) == payloads[index]
                result = sock
            else:
                kind = "socks" if mode.endswith("socks") else "http" if mode.endswith("http") else "tcp"
                reader, writer = await Suite.connect(self, kind, endpoint)
                connections.append((reader, writer))
                writer.write(payloads[index])
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(size), 10) == payloads[index]
                result = (reader, writer)
            setup.append((time.monotonic() - started) * 1000)
            return result
        try:
            channels = await asyncio.gather(*(connect(i) for i in range(count)))
            before = {role: stats(pid) for role, pid in roles.items()}
            peaks = {role: dict(sample) for role, sample in before.items()}
            cpu_before = cgroup_cpu()
            async def sample():
                while True:
                    for role, pid in roles.items():
                        for key, value in stats(pid).items():
                            peaks[role][key] = max(peaks[role].get(key, 0), value)
                    await asyncio.sleep(.05)
            start = time.monotonic()
            deadline = start + self.args.seconds
            async def exchange(index, channel):
                rounds = 0
                payload = payloads[index]
                while time.monotonic() < deadline:
                    at = time.monotonic()
                    if datagram:
                        await loop.sock_sendall(channel, payload)
                        received = await asyncio.wait_for(loop.sock_recv(channel, 65535), 5)
                    else:
                        reader, writer = channel
                        writer.write(payload)
                        await writer.drain()
                        received = await asyncio.wait_for(reader.readexactly(size), 5)
                    if received != payload:
                        raise AssertionError("payload corruption")
                    timings.append((time.monotonic() - at) * 1000)
                    rounds += 1
                return rounds
            sampler = asyncio.create_task(sample())
            try:
                rounds = await asyncio.gather(*(exchange(i, channel) for i, channel in enumerate(channels)))
            finally:
                sampler.cancel()
                await asyncio.gather(sampler, return_exceptions=True)
            elapsed = time.monotonic() - start
            after = {role: stats(pid) for role, pid in roles.items()}
            cpu_after = cgroup_cpu()
            total = sum(rounds) * size
            self.record(name, duration_seconds=round(elapsed, 6), concurrency=count, payload_bytes=size,
                verified_roundtrips=sum(rounds), verified_bytes_each_direction=total,
                payload_mbps_each_direction=round(total * 8 / elapsed / 1e6, 3),
                bulk_roundtrip=percentiles(timings), latency_samples=len(timings),
                setup_and_first_exchange=percentiles(setup),
                cpu_percent_one_core={role: round(100 * (after[role]["cpu_seconds"] - before[role]["cpu_seconds"]) / elapsed, 2) for role in roles},
                processes_before=before, sampled_peaks=peaks, processes_after=after,
                cgroup_cpu_delta={key: cpu_after[key] - cpu_before[key] for key in cpu_before})
        finally:
            for _, writer in connections:
                self.owned_writers.discard(writer)
            await asyncio.gather(*(close(writer) for _, writer in connections), return_exceptions=True)
            for sock in sockets:
                sock.close()

    async def run(self):
        current = "setup"
        try:
            await self.setup()
            for repeat in range(self.args.repeats):
                if self.args.direct:
                    for protocol in sorted({"udp" if mode.endswith("udp") else "tcp" for mode in self.args.modes}):
                        for count in self.args.levels:
                            current = f"direct/{protocol}/repeat-{repeat + 1}/concurrent-{count}"
                            await self.measure(current, self.udp_port if protocol == "udp" else self.target_port,
                                f"forward-{protocol}", count, {"harness": os.getpid()})
                transports = self.args.transports[repeat % len(self.args.transports):] + self.args.transports[:repeat % len(self.args.transports)]
                for scheme in transports:
                    async with self.stack(scheme) as (endpoints, roles):
                        for mode in self.args.modes:
                            for count in self.args.levels:
                                current = f"{scheme}/{mode}/repeat-{repeat + 1}/concurrent-{count}"
                                await self.measure(current, endpoints[mode], mode, count, roles)
        except Exception as exc:
            self.record(current, "fail", error=f"{type(exc).__name__}: {exc}")
        finally:
            await asyncio.gather(*(self.stop(p) for p in self.processes))
            for writer in tuple(self.owned_writers):
                await close(writer)
            for writer in tuple(self.writers):
                writer.close()
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
            if hasattr(self, "target"):
                self.target.close()
                await self.target.wait_closed()
            if hasattr(self, "udp"):
                self.udp.close()
            await self.receipt()
        return int(any(row["status"] != "pass" for row in self.results))

    async def receipt(self):
        failed = any(row["status"] != "pass" for row in self.results)
        hashes = {file: digest(Path(__file__).with_name(file)) for file in
                  ("profile_core.py", "qualify_runtime.py", "qualify.py", "qualify_quotas.py", "qualify_wan.py")}
        if hashes != self.source_hashes:
            self.record("measurement/source-changed", "fail", error="runner/helper files changed during measurement")
            failed = True
        metadata = {"state": "failed" if failed else "completed", "exit_code": int(failed),
            "elapsed_seconds": round(time.time() - self.started, 3), "binary_sha256": digest(self.binary),
            "source_hashes": self.source_hashes, "source_hashes_after": hashes,
            "results_sha256": digest(self.out / "results.json"),
            "platform": platform.platform(), "affinity_cpus": sorted(os.sched_getaffinity(0)),
            "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
            "memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
            "args": {k: str(v) if isinstance(v, Path) else v for k, v in vars(self.args).items()},
            "latency_sampling": "every roundtrip after untimed warmup; nearest-rank percentiles",
            "resource_sampling_seconds": .05, "cpu_unit": "100 percent equals one CPU core",
            "scope": "shared-host loopback; verified mTLS; explicitly configured quota/worker/heartbeat policy; no maximum capacity or WAN/SLO claim"}
        (self.out / "completion.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transports", default="wss,https,wts")
    parser.add_argument("--modes", default="forward-tcp")
    parser.add_argument("--levels", default="1,16,64,128")
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--quotas", choices=("off", "default"), default="off")
    parser.add_argument("--payload-bytes", type=int, default=65536)
    parser.add_argument("--datagram-bytes", type=int, default=1200)
    parser.add_argument("--direct", action="store_true")
    args = parser.parse_args()
    args.transports, args.modes = args.transports.split(","), args.modes.split(",")
    try:
        args.levels = [int(value) for value in args.levels.split(",")]
    except ValueError:
        parser.error("levels must be comma-separated integers")
    if not __debug__:
        parser.error("Python assertions must be enabled")
    if not args.transports or any(s not in ("wss", "https", "wts") for s in args.transports):
        parser.error("transports: wss,https,wts")
    if not args.modes or any(mode not in MODES for mode in args.modes):
        parser.error("unsupported mode")
    if not args.levels or any(not 1 <= n <= 128 for n in args.levels) or len(set(args.levels)) != len(args.levels):
        parser.error("levels must be unique and between 1 and 128")
    if not 1 <= args.seconds <= 30 or not 1 <= args.repeats <= 5 or not 1 <= args.workers <= 4:
        parser.error("seconds: 1..30; repeats: 1..5; workers: 1..4")
    if not 1024 <= args.payload_bytes <= 1048576 or not 64 <= args.datagram_bytes <= 40000:
        parser.error("payload-bytes: 1024..1048576; datagram-bytes: 64..40000")
    if args.quotas == "default" and max(args.levels) > 16:
        parser.error("default quota profile is limited to 16 concurrent streams")
    if not Path("/proc/self/stat").exists():
        parser.error("Linux /proc required")
    raise SystemExit(asyncio.run(CoreProfile(args).run()))


if __name__ == "__main__":
    main()
