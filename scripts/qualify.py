#!/usr/bin/env python3
"""Bounded loopback qualification. Exit 1 means a measured check failed.

Run: python3 scripts/qualify.py --binary target/release/tunward
No external targets, dependencies, firewall changes, or privileged operations.
"""

import argparse
import asyncio
import base64
import contextvars
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import socket
import struct
import time


USED_PORTS = set()
CHECK_FAILURES = contextvars.ContextVar("qualification_check_failures", default=None)


def port():
    # SOCKS5 and QUIC also bind UDP; a TCP-only probe misses those listeners.
    for _ in range(1000):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            candidate = tcp.getsockname()[1]
            if candidate in USED_PORTS:
                continue
            try:
                udp.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            USED_PORTS.add(candidate)
            return candidate
    raise RuntimeError("cannot find a free TCP/UDP port")


def stats(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
        return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                "rss_kib": int(status["VmRSS"].split()[0]),
                "peak_rss_kib": int(status["VmHWM"].split()[0]),
                "fds": len(list(Path(f"/proc/{pid}/fd").iterdir())),
                "threads": int(status["Threads"])}
    except (OSError, KeyError, ValueError):
        return {}


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, asyncio.TimeoutError):
        pass


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


class Suite:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.output or f"target/qualification/{time.strftime('%Y%m%d-%H%M%S')}").resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.binary = self.out / "tunward-under-test"
        shutil.copy2(Path(args.binary).resolve(), self.binary)
        self.processes = []
        self.results = []
        self.echo_port = None
        self.udp_port = None
        self.owned_writers = set()
        self.echo_accepted = 0
        self.stack_serial = 0

    def record(self, name, status="pass", **data):
        row = {"name": name, "status": status, **data}
        counter = CHECK_FAILURES.get()
        if status == "fail" and counter is not None:
            counter[0] += 1
        self.results.append(row)
        temporary = self.out / "results.next.json"
        temporary.write_text(json.dumps(self.results, indent=2))
        temporary.replace(self.out / "results.json")
        print(json.dumps(row), flush=True)

    async def spawn(self, label, *args, pipe=False, extra_env=None, log_level="WARN", workers=1, preexec_fn=None):
        if args[0] == "server":
            is_deny_test = "--deny-by-default-test" in args
            args = tuple(a for a in args if a != "--deny-by-default-test")
            if (
                not is_deny_test
                and not any(str(a).startswith(("--restrict-config", "--restrict-to")) for a in args)
                and getattr(self, "policy", None) is not None
            ):
                args = (args[0], "--restrict-config", str(self.policy)) + args[1:]
        if args[0] == "client" and any(str(a).startswith(("wss://", "https://", "wts://")) for a in args) and not any(str(a).startswith("--tls-verify-certificate") for a in args):
            args += ("--tls-verify-certificate=false",)
        env = {k: v for k, v in os.environ.items() if k not in
               ("NO_COLOR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "RUST_LOG", "TOKIO_WORKER_THREADS")
               and not k.startswith("TUNWARD_")}
        env["NO_COLOR"] = "true"
        env.update(extra_env or {})
        log = open(self.out / f"{label}.log", "wb")
        try:
            proc = await asyncio.create_subprocess_exec(
                str(self.binary), *args, "--nb-worker-threads", str(workers), "--log-lvl", log_level,
                env=env, stdin=asyncio.subprocess.PIPE if pipe else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE if pipe else log, stderr=log, start_new_session=True,
                preexec_fn=preexec_fn)
        finally:
            log.close()
        self.processes.append(proc)
        return proc

    async def stop(self, proc):
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    async def ready(self, p, proc):
        for _ in range(100):
            if proc.returncode is not None:
                raise RuntimeError(f"process exited {proc.returncode}; see logs")
            try:
                r, w = await asyncio.open_connection("127.0.0.1", p)
                await close(w)
                return
            except OSError:
                await asyncio.sleep(.05)
        raise TimeoutError(f"listener {p} not ready")

    async def check(self, name, fn, timeout=20):
        start = time.monotonic()
        counter = [0]
        token = CHECK_FAILURES.set(counter)
        try:
            details = await asyncio.wait_for(fn(), timeout)
            status = "fail" if counter[0] else "pass"
            data = {**({"failed_child_checks": counter[0]} if counter[0] else {}), **(details or {})}
        except Exception as exc:
            status = "fail"
            data = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            CHECK_FAILURES.reset(token)
        self.record(name, status, elapsed_seconds=round(time.monotonic() - start, 3), **data)

    async def connect(self, mode, endpoint):
        if mode == "unix":
            r, w = await asyncio.open_unix_connection(endpoint)
        else:
            r, w = await asyncio.open_connection("127.0.0.1", endpoint)
        self.owned_writers.add(w)
        try:
            if mode == "socks":
                w.write(b"\x05\x01\x00")
                await w.drain()
                assert await r.readexactly(2) == b"\x05\x00", "SOCKS negotiation failed"
                w.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.echo_port))
                await w.drain()
                h = await r.readexactly(4)
                assert h[:2] == b"\x05\x00", f"SOCKS reply {h.hex()}"
                n = {1: 4, 4: 16}.get(h[3])
                if n is None:
                    n = (await r.readexactly(1))[0]
                await r.readexactly(n + 2)
            elif mode == "http":
                w.write(f"CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
                await w.drain()
                h = await r.readuntil(b"\r\n\r\n")
                assert b" 200 " in h.split(b"\r\n")[0], f"CONNECT reply {h[:100]!r}"
            return r, w
        except BaseException:
            self.owned_writers.discard(w)
            await close(w)
            raise

    async def exchange(self, mode, endpoint, size=1024, rounds=1):
        start = time.monotonic()
        r, w = await self.connect(mode, endpoint)
        try:
            data = os.urandom(size)
            for _ in range(rounds):
                w.write(data)
                await w.drain()
                assert await r.readexactly(size) == data, "payload corrupted"
            return (time.monotonic() - start) * 1000
        finally:
            self.owned_writers.discard(w)
            await close(w)

    async def batch(self, mode, endpoint, count, size=1024, rounds=1, timeout=8):
        start = time.monotonic()
        outcomes = await asyncio.gather(*(asyncio.wait_for(self.exchange(mode, endpoint, size, rounds), timeout)
                                          for _ in range(count)), return_exceptions=True)
        elapsed = time.monotonic() - start
        errors = [f"{type(x).__name__}: {x}" for x in outcomes if isinstance(x, BaseException)]
        timings = sorted(x for x in outcomes if not isinstance(x, BaseException))
        details = {"connections": count, "successful": count - len(errors), "errors": errors[:5],
                   "timeout_seconds_per_connection": timeout,
                   "payload_bytes_per_connection": size * rounds,
                   "payload_mbps_one_direction": round((count - len(errors)) * size * rounds * 8 / elapsed / 1e6, 3)}
        if timings:
            details["connection_and_exchange_p50_ms"] = round(timings[int((len(timings) - 1) * .50)], 3)
            details["connection_and_exchange_p95_ms"] = round(timings[int((len(timings) - 1) * .95)], 3)
            details["connection_and_exchange_p99_ms"] = round(timings[int((len(timings) - 1) * .99)], 3)
        assert not errors, json.dumps(details)
        return details

    async def udp(self, endpoint, size, count=16):
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            s.connect(("127.0.0.1", endpoint))
            for seq in range(count):
                data = struct.pack("!I", seq) + os.urandom(size - 4)
                await loop.sock_sendall(s, data)
                got = await asyncio.wait_for(loop.sock_recv(s, 65535), 2)
                assert got == data, f"datagram mismatch: sent={len(data)} received={len(got)}"
        return {"datagrams": count, "bytes_per_datagram": size}

    async def api(self, p, path):
        r, w = await asyncio.open_connection("127.0.0.1", p)
        try:
            w.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            h = await r.readuntil(b"\r\n\r\n")
            assert b" 200 " in h.split(b"\r\n")[0], h[:100]
            return json.loads(await r.read())
        finally:
            await close(w)

    async def stack(self, scheme):
        self.stack_serial += 1
        label = f"{scheme}-{self.stack_serial}"
        sp, mp = port(), port()
        server = await self.spawn(f"{label}-server", "server", f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}",
                                  "--management-api", f"127.0.0.1:{mp}",
                                  "--remote-to-local-server-idle-timeout", "5s")
        await self.ready(sp, server)
        endpoints = {k: port() for k in ("tcp", "udp", "socks", "http", "reverse-tcp", "reverse-udp", "reverse-socks", "reverse-http")}
        endpoints["unix"] = str(self.out / f"{label}-local.sock")
        endpoints["reverse-unix"] = str(self.out / f"{label}-remote.sock")
        options = []
        for key, proto in (("tcp", "tcp"), ("udp", "udp"), ("socks", "socks5"), ("http", "http")):
            target = f":127.0.0.1:{self.udp_port if proto == 'udp' else self.echo_port}" if key in ("tcp", "udp") else ""
            options += ["-L", f"{proto}://127.0.0.1:{endpoints[key]}{target}"]
        options += ["-L", f"unix://{endpoints['unix']}:127.0.0.1:{self.echo_port}"]
        for key, proto in (("reverse-tcp", "tcp"), ("reverse-udp", "udp"), ("reverse-socks", "socks5"), ("reverse-http", "http")):
            target = f":127.0.0.1:{self.udp_port if proto == 'udp' else self.echo_port}" if proto in ("tcp", "udp") else ""
            options += ["-R", f"{proto}://127.0.0.1:{endpoints[key]}{target}"]
        options += ["-R", f"unix://{endpoints['reverse-unix']}:127.0.0.1:{self.echo_port}"]
        client = await self.spawn(f"{label}-client", "client", *options, "--client-id", f"qualification-{scheme}",
                                  "--connection-retry-max-backoff", "2s", f"{scheme}://127.0.0.1:{sp}")
        await self.ready(endpoints["tcp"], client)
        await asyncio.sleep(.5)
        return server, client, endpoints, sp, mp

    async def protocol(self, scheme):
        server, client, ep, sp, mp = await self.stack(scheme)
        pids = [server.pid, client.pid]
        baseline = {str(p): stats(p) for p in pids}
        try:
            for key, mode in (("tcp", "tcp"), ("socks", "socks"), ("http", "http"), ("unix", "unix"),
                              ("reverse-tcp", "tcp"), ("reverse-socks", "socks"), ("reverse-http", "http"),
                              ("reverse-unix", "unix")):
                await self.check(f"{scheme}/{key}/concurrent-16", lambda m=mode, e=ep[key]: self.batch(m, e, 16))
            for key in ("udp", "reverse-udp"):
                for size in (64, 1200, 40000):
                    await self.check(f"{scheme}/{key}/datagram-{size}", lambda e=ep[key], s=size: self.udp(e, s), 5)
            for concurrency in (1, 16, 64, 128):
                await self.check(f"{scheme}/tcp/load-{concurrency}",
                                 lambda n=concurrency: self.batch("tcp", ep["tcp"], n, 65536, 4))
                await asyncio.sleep(.2)

            async def sustained():
                connections = await asyncio.gather(*(self.connect("tcp", ep["tcp"]) for _ in range(8)))
                before = {str(p): stats(p) for p in pids}
                start = time.monotonic()
                transferred = 0
                data = os.urandom(65536)
                async def roundtrip(r, w):
                    w.write(data)
                    await w.drain()
                    assert await r.readexactly(len(data)) == data, "sustained payload corrupted"
                try:
                    while time.monotonic() - start < self.args.hold:
                        await asyncio.gather(*(roundtrip(r, w) for r, w in connections))
                        transferred += len(data) * len(connections)
                        # Cap application payload to 20 MiB/s in each direction.
                        await asyncio.sleep(max(0, transferred / (20 * 1024 * 1024) - (time.monotonic() - start)))
                    elapsed = time.monotonic() - start
                    after = {str(p): stats(p) for p in pids}
                    return {"verified_payload_bytes_each_direction": transferred, "duration_seconds": round(elapsed, 3),
                            "mbps_each_direction": round(transferred * 8 / elapsed / 1e6, 3),
                            "processes": {str(p): {"before": before[str(p)], "after": after[str(p)],
                                "cpu_percent_of_one_core": round(100 * (after[str(p)]["cpu_seconds"] - before[str(p)]["cpu_seconds"]) / elapsed, 2)} for p in pids}}
                finally:
                    for _, w in connections:
                        self.owned_writers.discard(w)
                        await close(w)
            await self.check(f"{scheme}/tcp/sustained-bounded", sustained, self.args.hold + 10)

            async def idle():
                connections = []
                try:
                    for _ in range(self.args.idle):
                        r, w = await self.connect("tcp", ep["tcp"])
                        w.write(b"idle")
                        await w.drain()
                        assert await r.readexactly(4) == b"idle"
                        connections.append((r, w))
                    before = {str(p): stats(p) for p in pids}
                    await asyncio.sleep(self.args.hold)
                    after = {str(p): stats(p) for p in pids}
                    for r, w in connections:
                        w.write(b"wake")
                        await w.drain()
                        assert await r.readexactly(4) == b"wake"
                    return {"established_tunnels": len(connections), "hold_seconds": self.args.hold,
                            "before": before, "after": after}
                finally:
                    for _, w in connections:
                        self.owned_writers.discard(w)
                        await close(w)
            await self.check(f"{scheme}/tcp/idle", idle, self.args.hold + 20)
            await asyncio.sleep(6)
            health = await self.api(mp, "/healthz")
            self.record(f"{scheme}/resources", baseline=baseline,
                        after_cooldown={str(p): stats(p) for p in pids}, health=health,
                        note="Reverse listeners remain running; RSS includes allocator retention, not proof of a leak.")

            async def stdio():
                proc = await self.spawn(f"{scheme}-stdio", "client", "-L", f"stdio://127.0.0.1:{self.echo_port}",
                                        f"{scheme}://127.0.0.1:{sp}", pipe=True)
                try:
                    data = os.urandom(32768)
                    proc.stdin.write(data)
                    await proc.stdin.drain()
                    assert await proc.stdout.readexactly(len(data)) == data, "stdio payload mismatch"
                    return {"bytes": len(data)}
                finally:
                    await self.stop(proc)
            await self.check(f"{scheme}/stdio", stdio, 8)

            async def recovery():
                await self.stop(server)
                replacement = await self.spawn(f"{scheme}-server-restarted", "server",
                                                f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}")
                try:
                    await self.ready(sp, replacement)
                    start = time.monotonic()
                    for _ in range(30):
                        try:
                            await asyncio.wait_for(self.exchange("tcp", ep["tcp"]), 12)
                            return {"recovery_seconds": round(time.monotonic() - start, 3)}
                        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                            await asyncio.sleep(.2)
                    raise TimeoutError("forward tunnel did not recover")
                finally:
                    await self.stop(replacement)
            await self.check(f"{scheme}/restart-recovery", recovery, 32)
        finally:
            await self.stop(client)
            await self.stop(server)

    async def fleet(self):
        sp, mp = port(), port()
        server = await self.spawn("fleet-server", "server", f"ws://127.0.0.1:{sp}", "--management-api", f"127.0.0.1:{mp}",
                                  "--remote-to-local-server-idle-timeout", "3s")
        clients = []
        try:
            await self.ready(mp, server)
            baseline = stats(server.pid)
            async def one(i):
                client = await self.spawn(f"fleet-client-{i}", "client", "-R", f"tcp://127.0.0.1:0:127.0.0.1:{self.echo_port}",
                                          "--client-id", f"device-{i}", f"ws://127.0.0.1:{sp}")
                clients.append(client)
            await asyncio.gather(*(one(i) for i in range(self.args.devices)))
            for _ in range(100):
                health = await self.api(mp, "/healthz")
                if health["active_clients"] >= self.args.devices:
                    break
                await asyncio.sleep(.1)
            records = await self.api(mp, "/api/v1/clients")
            assigned = [r["assigned_port"] for r in records if r.get("assigned_port")]
            assert len(assigned) == self.args.devices, f"registered {len(assigned)} / {self.args.devices}"
            outcomes = await asyncio.gather(*(asyncio.wait_for(self.exchange("tcp", p), 8) for p in assigned), return_exceptions=True)
            failures = [str(x) for x in outcomes if isinstance(x, BaseException)]
            self.record("fleet/device-tunnels", "fail" if failures else "pass", devices=self.args.devices,
                        successful=len(assigned) - len(failures), errors=failures[:5], health=health,
                        server_baseline=baseline, server_loaded=stats(server.pid),
                        client_rss_kib=sum(stats(c.pid).get("rss_kib", 0) for c in clients))
            await asyncio.gather(*(self.stop(c) for c in clients))
            await asyncio.sleep(6)
            health = await self.api(mp, "/healthz")
            self.record("fleet/disconnect-cleanup", "pass" if health["active_clients"] == 0 and health["active_sessions"] == 0 else "fail",
                        health=health, server_after=stats(server.pid), cooldown_seconds=6)
        finally:
            await asyncio.gather(*(self.stop(c) for c in clients))
            await self.stop(server)

    async def security(self):
        sp, lp = port(), port()
        server = await self.spawn("security-server", "server", f"ws://127.0.0.1:{sp}",
                                  "--restrict-to", f"127.0.0.1:{self.echo_port}", "-r", "qualification-secret")
        clients = []
        try:
            await self.ready(sp, server)
            async def restriction(name, target, prefix, allowed):
                p = port()
                c = await self.spawn(f"security-{name}", "client", "-L", f"tcp://127.0.0.1:{p}:127.0.0.1:{target}",
                                     "-P", prefix, "--connection-retry-max-backoff", "1s", f"ws://127.0.0.1:{sp}")
                clients.append(c)
                await self.ready(p, c)
                try:
                    await asyncio.wait_for(self.exchange("tcp", p), 3)
                    succeeded = True
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    succeeded = False
                assert succeeded == allowed, f"observed success={succeeded}, expected={allowed}"
                return {"allowed": succeeded}
            await self.check("security/restriction-allowed-control", lambda: restriction("allow", self.echo_port, "qualification-secret", True))
            await self.check("security/restriction-denied-target", lambda: restriction("target", self.other_echo_port, "qualification-secret", False))
            await self.check("security/restriction-denied-path", lambda: restriction("path", self.echo_port, "wrong", False))

            # Priority 3: Deny tunnel access without an explicit policy (even with --allow-insecure-dev)
            bare_sp = port()
            bare_server = await self.spawn("security-deny-default-server", "server", f"ws://127.0.0.1:{bare_sp}",
                                           "--allow-insecure-dev", "--deny-by-default-test")
            await self.ready(bare_sp, bare_server)
            async def test_denied_without_policy():
                dp = port()
                c = await self.spawn("security-deny-client", "client", "-L", f"tcp://127.0.0.1:{dp}:127.0.0.1:{self.echo_port}",
                                     "--connection-retry-max-backoff", "1s", f"ws://127.0.0.1:{bare_sp}")
                clients.append(c)
                await self.ready(dp, c)
                try:
                    await asyncio.wait_for(self.exchange("tcp", dp), 2)
                    success = True
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    success = False
                assert not success, "Expected tunnel connection to be rejected when no restriction policy is configured"
                return {"denied": not success}
            await self.check("security/deny-without-explicit-policy", test_denied_without_policy)
            await self.stop(bare_server)

            async def malformed():
                payloads = [b"not-http\r\n\r\n", b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"]
                async def one(i):
                    r, w = await asyncio.open_connection("127.0.0.1", sp)
                    try:
                        w.write(payloads[i % len(payloads)])
                        await w.drain()
                        try:
                            await asyncio.wait_for(r.read(4096), 1)
                        except (OSError, asyncio.TimeoutError):
                            pass
                    finally:
                        await close(w)
                await asyncio.gather(*(one(i) for i in range(32)))
                assert server.returncode is None, "server exited"
                return await restriction("post-malformed", self.echo_port, "qualification-secret", True)
            await self.check("security/bounded-malformed-input-resilience", malformed)
        finally:
            for c in clients:
                await self.stop(c)
            await self.stop(server)

    async def extended(self):
        async def command(*args):
            proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, stderr = await proc.communicate()
            assert proc.returncode == 0, stderr.decode(errors="replace")

        certs = self.out / "test-certificates"
        certs.mkdir(mode=0o700)
        await command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-days", "1", "-subj", "/CN=Qualification CA", "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-keyout", str(certs / "ca.key"), "-out", str(certs / "ca.pem"))
        for name, cn, eku in (("server", "localhost", "serverAuth"), ("client", "v1", "clientAuth")):
            await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                          "-subj", f"/CN={cn}", "-keyout", str(certs / f"{name}.key"), "-out", str(certs / f"{name}.csr"))
            ext = certs / f"{name}.ext"
            ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\n"
                           "subjectAltName=IP:127.0.0.1,DNS:localhost\n")
            await command("openssl", "x509", "-req", "-in", str(certs / f"{name}.csr"), "-CA", str(certs / "ca.pem"),
                          "-CAkey", str(certs / "ca.key"), "-set_serial", "10" if name == "server" else "11", "-days", "1",
                          "-extfile", str(ext), "-out", str(certs / f"{name}.pem"))

        for scheme in ("wss", "https", "wts"):
            sp = port()
            srv = await self.spawn(f"tls-{scheme}-server", "server", f"wts://127.0.0.1:{sp}",
                                   "--tls-certificate", str(certs / "server.pem"), "--tls-private-key", str(certs / "server.key"),
                                   "--tls-client-ca-certs", str(certs / "ca.pem"))
            try:
                await self.ready(sp, srv)
                for name, identity, trusted, allowed in (("valid", True, True, True), ("missing-client", False, True, False),
                                                          ("untrusted-server", True, False, False)):
                    async def tls_case(n=name, ident=identity, trust=trusted, permit=allowed):
                        p = port()
                        options = ["--tls-verify-certificate"]
                        if ident:
                            options += ["--tls-certificate", str(certs / "client.pem"), "--tls-private-key", str(certs / "client.key")]
                        c = await self.spawn(f"tls-{scheme}-{n}", "client", "-L", f"tcp://127.0.0.1:{p}:127.0.0.1:{self.echo_port}",
                                             *options, "--connection-retry-max-backoff", "1s", f"{scheme}://127.0.0.1:{sp}",
                                             extra_env={"SSL_CERT_FILE": str(certs / ("ca.pem" if trust else "client.pem")), "SSL_CERT_DIR": ""})
                        try:
                            await self.ready(p, c)
                            try:
                                await asyncio.wait_for(self.exchange("tcp", p), 4)
                                success = True
                            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                                success = False
                            assert success == permit, f"success={success}, expected={permit}"
                            return {"verified_echo": success}
                        finally:
                            await self.stop(c)
                    await self.check(f"security/{scheme}/mtls-{name}", tls_case, 8)
            finally:
                await self.stop(srv)

        for scheme in self.args.transports.split(","):
            sp, socks, http = port(), port(), port()
            srv = await self.spawn(f"auth-{scheme}-server", "server", f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}")
            client = None
            try:
                await self.ready(sp, srv)
                client = await self.spawn(f"auth-{scheme}-client", "client", "-L", f"socks5://127.0.0.1:{socks}?login=testuser&password=qualification-password",
                                          "-L", f"http://127.0.0.1:{http}?login=testuser&password=qualification-password",
                                          f"{scheme}://127.0.0.1:{sp}", log_level="INFO")
                await self.ready(socks, client)
                async def socks_auth(password, allowed):
                    r, w = await asyncio.open_connection("127.0.0.1", socks)
                    try:
                        w.write(b"\x05\x01\x02")
                        await w.drain()
                        assert await r.readexactly(2) == b"\x05\x02"
                        user, pw = b"testuser", password.encode()
                        w.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
                        await w.drain()
                        answer = await r.readexactly(2)
                        assert (answer == b"\x01\x00") == allowed, f"auth reply {answer.hex()}"
                        if allowed:
                            w.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.echo_port))
                            await w.drain()
                            response = await r.readexactly(10)
                            assert response[1] == 0, response.hex()
                            w.write(b"authenticated")
                            await w.drain()
                            assert await r.readexactly(13) == b"authenticated"
                    finally:
                        await close(w)
                async def http_auth(password, allowed):
                    r, w = await asyncio.open_connection("127.0.0.1", http)
                    try:
                        token = base64.b64encode(f"testuser:{password}".encode()).decode()
                        w.write(f"CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode())
                        await w.drain()
                        h = await r.readuntil(b"\r\n\r\n")
                        assert (b" 200 " in h.split(b"\r\n")[0]) == allowed, h[:100]
                        if allowed:
                            w.write(b"authenticated")
                            await w.drain()
                            assert await r.readexactly(13) == b"authenticated"
                        else:
                            assert b" 407 " in h.split(b"\r\n")[0], h[:100]
                    finally:
                        await close(w)
                for name, fn in (("socks5", socks_auth), ("http-proxy", http_auth)):
                    async def concurrent_auth(f=fn):
                        await asyncio.gather(*(f("qualification-password", True) for _ in range(8)))
                        await f("incorrect-password", False)
                        return {"valid_concurrent": 8, "invalid_rejected": 1}
                    await self.check(f"security/{scheme}/{name}-authentication", concurrent_auth)
                async def association_lifecycle():
                    r, w = await asyncio.open_connection("127.0.0.1", socks)
                    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    relay.setblocking(False)
                    relay.bind(("127.0.0.1", 0))
                    try:
                        w.write(b"\x05\x01\x02")
                        await w.drain()
                        assert await r.readexactly(2) == b"\x05\x02"
                        user, password = b"testuser", b"qualification-password"
                        w.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
                        await w.drain()
                        assert await r.readexactly(2) == b"\x01\x00"
                        w.write(b"\x05\x03\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", relay.getsockname()[1]))
                        await w.drain()
                        reply = await r.readexactly(10)
                        assert reply[:4] == b"\x05\x00\x00\x01", reply.hex()
                        relay.connect((socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0]))
                        header = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.udp_port)
                        loop = asyncio.get_running_loop()
                        for i in range(16):
                            packet = header + struct.pack("!I", i) + os.urandom(128)
                            await loop.sock_sendall(relay, packet)
                            assert await asyncio.wait_for(loop.sock_recv(relay, 4096), 3) == packet
                        await close(w)
                        await asyncio.sleep(.2)
                        packet = header + b"closed-association-control"
                        await loop.sock_sendall(relay, packet)
                        try:
                            received = await asyncio.wait_for(loop.sock_recv(relay, 4096), .5)
                        except (asyncio.TimeoutError, ConnectionRefusedError):
                            received = None
                        assert received is None, "UDP relay still forwarded after authenticated TCP association closed"
                        return {"verified_datagrams": 16, "closed_association_rejected": True}
                    finally:
                        relay.close()
                        await close(w)
                await self.check(f"security/{scheme}/socks5-udp-association-lifecycle", association_lifecycle, 8)
                received_headers = []
                async def origin(r, w):
                    try:
                        headers = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 3)
                        received_headers.append(headers)
                        reply_body = b"origin-ok"
                        if headers.startswith(b"POST "):
                            body = bytearray()
                            if b"transfer-encoding: chunked" in headers.lower():
                                while True:
                                    n = int((await r.readline()).strip().split(b";")[0], 16)
                                    if n == 0:
                                        assert await r.readline() == b"\r\n"
                                        break
                                    body.extend(await r.readexactly(n))
                                    assert await r.readexactly(2) == b"\r\n"
                            else:
                                n = next(int(h.split(b":", 1)[1]) for h in headers.lower().split(b"\r\n") if h.startswith(b"content-length:"))
                                body.extend(await r.readexactly(n))
                            reply_body = hashlib.sha256(body).hexdigest().encode()
                        w.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(reply_body)}\r\nConnection: close\r\n\r\n".encode() + reply_body)
                        await w.drain()
                    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                        pass
                    finally:
                        await close(w)
                origin_server = await asyncio.start_server(origin, "127.0.0.1", 0, backlog=128)
                origin_port = origin_server.sockets[0].getsockname()[1]
                async def get(fragmented=False):
                    r, w = await asyncio.open_connection("127.0.0.1", http)
                    try:
                        token = base64.b64encode(b"testuser:qualification-password").decode()
                        request = f"GET http://127.0.0.1:{origin_port}/test HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nProxy-Authorization: Basic {token}\r\nConnection: close\r\n\r\n".encode()
                        if fragmented:
                            w.write(request[:2])
                            await w.drain()
                            await asyncio.sleep(.05)
                            w.write(request[2:])
                        else:
                            w.write(request)
                        await w.drain()
                        assert (await r.read()).endswith(b"origin-ok"), "ordinary HTTP proxy response missing"
                    finally:
                        await close(w)
                try:
                    async def get_load():
                        await asyncio.gather(*(get() for _ in range(16)))
                        return {"verified_http_requests": 16}
                    await self.check(f"{scheme}/http-proxy/ordinary-get-concurrent-16", get_load, 8)
                    self.record(f"security/{scheme}/http-proxy-origin-credential-isolation",
                                "fail" if any(b"proxy-authorization:" in h.lower() for h in received_headers) else "pass",
                                observed_origin_requests=len(received_headers),
                                note="Origin is a local test HTTP service, not an upstream proxy.")
                    await self.check(f"{scheme}/http-proxy/fragmented-get", lambda: get(True), 5)
                    async def post(chunked):
                        r, w = await asyncio.open_connection("127.0.0.1", http)
                        data = os.urandom(65536)
                        try:
                            token = base64.b64encode(b"testuser:qualification-password").decode()
                            framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(data)}"
                            w.write(f"POST http://127.0.0.1:{origin_port}/test HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic {token}\r\n{framing}\r\nConnection: close\r\n\r\n".encode())
                            for part in (data[:111], data[111:]):
                                w.write((f"{len(part):x}\r\n".encode() + part + b"\r\n") if chunked else part)
                                await w.drain()
                            if chunked:
                                w.write(b"0\r\n\r\n")
                                await w.drain()
                            assert (await r.read()).endswith(hashlib.sha256(data).hexdigest().encode())
                            return {"verified_body_bytes": len(data)}
                        finally:
                            await close(w)
                    for chunked in (False, True):
                        await self.check(f"{scheme}/http-proxy/post-{'chunked' if chunked else 'length'}", lambda c=chunked: post(c), 8)
                    async def reauthentication():
                        r, w = await asyncio.open_connection("127.0.0.1", http)
                        try:
                            token = base64.b64encode(b"testuser:qualification-password").decode()
                            request = f"GET http://127.0.0.1:{origin_port}/test HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode()
                            w.write(request)
                            await w.drain()
                            assert b" 200 " in (await r.readuntil(b"\r\n\r\n")).split(b"\r\n")[0]
                            assert await r.readexactly(9) == b"origin-ok"
                            w.write(request.replace(f"Proxy-Authorization: Basic {token}\r\n".encode(), b""))
                            await w.drain()
                            assert b" 407 " in (await r.readuntil(b"\r\n\r\n")).split(b"\r\n")[0]
                            return {"second_unauthenticated_request_rejected": True}
                        finally:
                            await close(w)
                    await self.check(f"security/{scheme}/http-proxy-per-request-authentication", reauthentication, 8)
                finally:
                    origin_server.close()
                    await origin_server.wait_closed()
                text = (self.out / f"auth-{scheme}-client.log").read_text()
                self.record(f"security/{scheme}/credential-log-redaction", "fail" if "qualification-password" in text else "pass",
                            note="Synthetic test password only; checked INFO startup logs.")
                await self.check(f"{scheme}/udp/load-16-peers", lambda: self.udp_load(sp, scheme), 15)
            finally:
                if client:
                    await self.stop(client)
                await self.stop(srv)

    async def udp_load(self, sp, scheme):
        p = port()
        c = await self.spawn(f"udp-load-{scheme}", "client", "-L", f"udp://127.0.0.1:{p}:127.0.0.1:{self.udp_port}", f"{scheme}://127.0.0.1:{sp}")
        try:
            await asyncio.sleep(.2)
            start = time.monotonic()
            await asyncio.gather(*(self.udp(p, 1200, 64) for _ in range(16)))
            return {"peers": 16, "verified_datagrams": 1024,
                    "payload_mbps_each_direction": round(1024 * 1200 * 8 / (time.monotonic() - start) / 1e6, 3)}
        finally:
            await self.stop(c)

    async def optimize(self):
        for workers in (1, 2, 4, 12):
            sp, lp = port(), port()
            srv = await self.spawn(f"workers-{workers}-server", "server", f"wss://127.0.0.1:{sp}", workers=workers)
            client = None
            try:
                await self.ready(sp, srv)
                client = await self.spawn(f"workers-{workers}-client", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}",
                                          f"wss://127.0.0.1:{sp}", workers=workers)
                await self.ready(lp, client)
                await self.batch("tcp", lp, 4, 65536, 4)
                before = {str(p.pid): stats(p.pid) for p in (srv, client)}
                runs = []
                for _ in range(3):
                    runs.append(await self.batch("tcp", lp, 16, 65536, 32))
                    await asyncio.sleep(.2)
                self.record(f"optimization/wss/workers-{workers}", runs=runs, before=before,
                            after={str(p.pid): stats(p.pid) for p in (srv, client)},
                            note="Three short bursts on shared host; not a capacity ceiling.")
            finally:
                if client:
                    await self.stop(client)
                await self.stop(srv)

    async def isolation(self):
        for scheme in self.args.transports.split(","):
            sp, lp = port(), port()
            srv = await self.spawn(f"isolated-{scheme}-server", "server", f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}")
            client = None
            try:
                await self.ready(sp, srv)
                client = await self.spawn(f"isolated-{scheme}-client", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{self.echo_port}",
                                          f"{scheme}://127.0.0.1:{sp}")
                await self.ready(lp, client)
                for n in (16, 128, 256):
                    await self.check(f"isolation/{scheme}/forward-tcp-{n}", lambda count=n: self.batch("tcp", lp, count, 16384, 4))
                for cycle in range(3):
                    await self.check(f"isolation/{scheme}/churn-{cycle}", lambda: self.batch("tcp", lp, 64))
                self.record(f"isolation/{scheme}/resources", server=stats(srv.pid), client=stats(client.pid))
            finally:
                if client:
                    await self.stop(client)
                await self.stop(srv)

        for scheme in ("ws", "wts"):
            sp, rp = port(), port()
            srv = await self.spawn(f"reverse-idle-{scheme}-server", "server", f"{'ws' if scheme == 'ws' else 'wts'}://127.0.0.1:{sp}")
            client = None
            try:
                await self.ready(sp, srv)
                baseline = self.echo_accepted
                client = await self.spawn(f"reverse-idle-{scheme}-client", "client", "-R", f"tcp://127.0.0.1:{rp}:127.0.0.1:{self.echo_port}",
                                          f"{scheme}://127.0.0.1:{sp}")
                await asyncio.sleep(1)
                unexpected = self.echo_accepted - baseline
                self.record(f"isolation/{scheme}/idle-reverse-upstream-connections", "pass" if unexpected == 0 else "fail",
                            upstream_connections_without_visitor=unexpected, client=stats(client.pid))
            finally:
                if client:
                    await self.stop(client)
                await self.stop(srv)

        async def after_eof(r, w):
            try:
                request = await asyncio.wait_for(r.read(), 5)
                if request == b"request":
                    w.write(b"response-after-fin")
                    await w.drain()
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                await close(w)
        fin_server = await asyncio.start_server(after_eof, "127.0.0.1", 0)
        target = fin_server.sockets[0].getsockname()[1]
        try:
            for scheme in self.args.transports.split(","):
                sp, lp = port(), port()
                srv = await self.spawn(f"fin-{scheme}-server", "server", f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}")
                client = None
                try:
                    await self.ready(sp, srv)
                    client = await self.spawn(f"fin-{scheme}-client", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{target}", f"{scheme}://127.0.0.1:{sp}")
                    await self.ready(lp, client)
                    async def half_close():
                        r, w = await asyncio.open_connection("127.0.0.1", lp)
                        try:
                            w.write(b"request")
                            await w.drain()
                            w.write_eof()
                            response = await r.read()
                            assert response == b"response-after-fin", f"response after EOF: {response!r}"
                        finally:
                            await close(w)
                    await self.check(f"isolation/{scheme}/tcp-half-close", half_close, 7)
                finally:
                    if client:
                        await self.stop(client)
                    await self.stop(srv)
        finally:
            fin_server.close()
            await fin_server.wait_closed()

    async def lifecycle(self):
        async def invalid_pool_config():
            for option, value, message in (("--connection-retry-max-backoff", "0s", b"must be greater than zero"),
                                           ("--connection-min-idle", "1001", b"must not exceed 1000")):
                proc = await self.spawn(f"invalid-{option[2:]}", "client", option, value, "ws://127.0.0.1:1")
                await asyncio.wait_for(proc.wait(), 3)
                log = (self.out / f"invalid-{option[2:]}.log").read_bytes()
                assert proc.returncode == 1 and message in log, f"invalid configuration aborted or was accepted: {proc.returncode}"
            return {"invalid_configurations_rejected_without_panic": 2}
        await self.check("lifecycle/client-pool-configuration-errors", invalid_pool_config, 8)
        async def one(scheme):
            observed_upload = asyncio.get_running_loop().create_future()
            async def early_eof(r, w):
                try:
                    assert await asyncio.wait_for(r.readexactly(5), 5) == b"start"
                    w.write_eof()
                    upload = await asyncio.wait_for(r.read(), 10)
                    if not observed_upload.done():
                        observed_upload.set_result(upload)
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    pass
                finally:
                    await close(w)
            async def delayed_reply(r, w):
                try:
                    request = await asyncio.wait_for(r.read(), 5)
                    if request == b"request":
                        await asyncio.sleep(6)
                        w.write(b"delayed-response-after-fin")
                        await w.drain()
                except (OSError, asyncio.TimeoutError):
                    pass
                finally:
                    await close(w)

            target = await asyncio.start_server(delayed_reply, "127.0.0.1", 0)
            early_target = await asyncio.start_server(early_eof, "127.0.0.1", 0)
            sp, lp, early_lp = port(), port(), port()
            srv = client = None
            try:
                srv = await self.spawn(f"lifecycle-{scheme}-server", "server",
                                       f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}",
                                       "--websocket-ping-frequency", "1s")
                await self.ready(sp, srv)
                client = await self.spawn(f"lifecycle-{scheme}-client", "client", "-L",
                                          f"tcp://127.0.0.1:{lp}:127.0.0.1:{target.sockets[0].getsockname()[1]}",
                                          "-L", f"tcp://127.0.0.1:{early_lp}:127.0.0.1:{early_target.sockets[0].getsockname()[1]}",
                                          "--websocket-ping-frequency", "1s", f"{scheme}://127.0.0.1:{sp}")
                await self.ready(lp, client)
                async def half_close():
                    r, w = await asyncio.open_connection("127.0.0.1", lp)
                    try:
                        w.write(b"request")
                        await w.drain()
                        w.write_eof()
                        assert await r.read() == b"delayed-response-after-fin", "response lost after heartbeat intervals"
                        return {"response_delay_seconds": 6, "heartbeat_seconds": 1}
                    finally:
                        await close(w)
                await self.check(f"lifecycle/{scheme}/half-close-with-heartbeats", half_close, 12)
                async def upload_after_eof():
                    r, w = await asyncio.open_connection("127.0.0.1", early_lp)
                    try:
                        w.write(b"start")
                        await w.drain()
                        assert await r.read() == b"", "server did not half-close"
                        await asyncio.sleep(6)
                        w.write(b"upload-after-peer-fin")
                        await w.drain()
                        w.write_eof()
                        assert await observed_upload == b"upload-after-peer-fin", "upload lost after heartbeat intervals"
                        return {"upload_delay_seconds": 6, "heartbeat_seconds": 1}
                    finally:
                        await close(w)
                await self.check(f"lifecycle/{scheme}/upload-after-peer-fin", upload_after_eof, 12)
            finally:
                if client:
                    await self.stop(client)
                if srv:
                    await self.stop(srv)
                target.close()
                early_target.close()
                await target.wait_closed()
                await early_target.wait_closed()
        await asyncio.gather(*(one(s) for s in self.args.transports.split(",")))

    async def certificate_rotation(self):
        certs = self.out / "rotation-certificates"
        certs.mkdir(mode=0o700)
        async def command(*args):
            proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, stderr = await proc.communicate()
            assert proc.returncode == 0, stderr.decode(errors="replace")
        await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", "/CN=localhost", "-keyout", str(certs / "server.key"), "-out", str(certs / "server.csr"))
        ext = certs / "server.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n")
        for name in ("a", "b"):
            await command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                          "-days", "4", "-subj", f"/CN=Rotation CA {name}", "-addext", "basicConstraints=critical,CA:TRUE",
                          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                          "-keyout", str(certs / f"ca-{name}.key"), "-out", str(certs / f"ca-{name}.pem"))
            await command("openssl", "x509", "-req", "-in", str(certs / "server.csr"), "-CA", str(certs / f"ca-{name}.pem"),
                          "-CAkey", str(certs / f"ca-{name}.key"), "-set_serial", "100" if name == "a" else "200", "-days", "4",
                          "-extfile", str(ext), "-out", str(certs / f"server-{name}.pem"))
        for scheme in ("wss", "https", "wts"):
            sp, lp = port(), port()
            live = certs / f"{scheme}-live.pem"
            live.write_bytes((certs / "server-a.pem").read_bytes())
            server = await self.spawn(f"rotation-{scheme}-server", "server", f"wts://127.0.0.1:{sp}",
                                      "--tls-certificate", str(live), "--tls-private-key", str(certs / "server.key"))
            clients = []
            held = None
            try:
                await self.ready(sp, server)
                async def make_client(label, ca):
                    p = port()
                    c = await self.spawn(f"rotation-{scheme}-{label}", "client", "-L", f"tcp://127.0.0.1:{p}:127.0.0.1:{self.echo_port}",
                                         "--tls-verify-certificate", "--connection-retry-max-backoff", "1s", f"{scheme}://127.0.0.1:{sp}",
                                         extra_env={"SSL_CERT_FILE": str(certs / f"ca-{ca}.pem"), "SSL_CERT_DIR": ""})
                    clients.append(c)
                    await self.ready(p, c)
                    return p
                p = await make_client("old", "a")
                held = await self.connect("tcp", p)
                async def held_echo():
                    r, w = held
                    w.write(b"established-session")
                    await w.drain()
                    assert await asyncio.wait_for(r.readexactly(19), 3) == b"established-session"
                await held_echo()
                # Replace the file inode, as certificate managers commonly do; no warm-up accepts.
                replacement = live.with_suffix(".next")
                replacement.write_bytes((certs / "server-b.pem").read_bytes())
                replacement.replace(live)
                await asyncio.sleep(7)
                async def rotated():
                    await held_echo()
                    new_port = await make_client("new", "b")
                    await self.exchange("tcp", new_port)
                    text = (self.out / f"rotation-{scheme}-new.log").read_text()
                    assert "UnknownIssuer" not in text, "first post-rotation handshake still used the old CA"
                    return {"replacement": "atomic rename", "settle_seconds": 7,
                            "new_trust_anchor_verified": True, "established_connection_preserved": True}
                await self.check(f"rotation/{scheme}/atomic-certificate-replacement", rotated, 10)
                async def invalid_replacement():
                    replacement.write_bytes(b"invalid certificate data\n")
                    replacement.replace(live)
                    await asyncio.sleep(2)
                    p = await make_client("invalid-keeps-last-good", "b")
                    await self.exchange("tcp", p)
                    await held_echo()
                    return {"last_valid_certificate_retained": True}
                await self.check(f"rotation/{scheme}/invalid-replacement-keeps-last-good", invalid_replacement, 10)
            finally:
                if held:
                    self.owned_writers.discard(held[1])
                    await close(held[1])
                await asyncio.gather(*(self.stop(c) for c in clients))
                await self.stop(server)

    async def capacity(self):
        for scheme in self.args.transports.split(","):
            server, client, ep, _, _ = await self.stack(scheme)
            pids = [server.pid, client.pid]
            try:
                await self.check(f"capacity/{scheme}/direct-control",
                                 lambda: self.batch("tcp", self.echo_port, 128, 16384, 4))
                for key, mode in (("tcp", "tcp"), ("socks", "socks"), ("http", "http"), ("unix", "unix"),
                                  ("reverse-tcp", "tcp"), ("reverse-socks", "socks"),
                                  ("reverse-http", "http"), ("reverse-unix", "unix")):
                    for count in self.args.capacity_levels:
                        async def measure(n=count, m=mode, endpoint=ep[key]):
                            before = {str(p): stats(p) for p in pids}
                            peaks = {str(p): dict(before[str(p)]) for p in pids}
                            async def sample():
                                while True:
                                    for p in pids:
                                        for metric, value in stats(p).items():
                                            peaks[str(p)][metric] = max(peaks[str(p)].get(metric, 0), value)
                                    await asyncio.sleep(.05)
                            sampler = asyncio.create_task(sample())
                            started = time.monotonic()
                            try:
                                runs = [await self.batch(m, endpoint, n, 16384, 4) for _ in range(2)]
                            finally:
                                sampler.cancel()
                                await asyncio.gather(sampler, return_exceptions=True)
                            elapsed = time.monotonic() - started
                            after = {str(p): stats(p) for p in pids}
                            assert all(after[str(p)].get("rss_kib", 0) < 1024 * 1024 for p in pids), "1 GiB per-process guard exceeded"
                            return {"runs": runs, "processes_before": before, "sampled_peaks": peaks,
                                    "processes_after": after, "sample_interval_seconds": .05,
                                    "cpu_percent_of_one_core": {str(p): round(100 * (after[str(p)]["cpu_seconds"] - before[str(p)]["cpu_seconds"]) / elapsed, 2) for p in pids}}
                        prior = len(self.results)
                        await self.check(f"capacity/{scheme}/{key}/concurrent-{count}", measure, 25)
                        if self.results[prior]["status"] == "fail":
                            break
                for key in ("udp", "reverse-udp"):
                    for count in (16, 64):
                        async def datagrams(n=count, endpoint=ep[key]):
                            start = time.monotonic()
                            await asyncio.gather(*(self.udp(endpoint, 1200, 4) for _ in range(n)))
                            return {"peers": n, "verified_datagrams": n * 4, "bytes_per_datagram": 1200,
                                    "duration_seconds": round(time.monotonic() - start, 3)}
                        await self.check(f"capacity/{scheme}/{key}/peers-{count}", datagrams, 15)
                await asyncio.sleep(6)
                self.record(f"capacity/{scheme}/cooldown", processes={str(p): stats(p) for p in pids},
                            note="Shared-host short bursts; sampled peaks can miss sub-50ms spikes. Not a production capacity ceiling.")
            finally:
                await self.stop(client)
                await self.stop(server)

    async def soak(self):
        async def one(scheme):
            srv, client, ep, sp, _ = await self.stack(scheme)
            connections = []
            try:
                pids = [srv.pid, client.pid]
                baseline = {str(p): stats(p) for p in pids}
                modes = (("tcp", "tcp"), ("socks", "socks"), ("http", "http"), ("unix", "unix"),
                         ("reverse-tcp", "tcp"), ("reverse-socks", "socks"),
                         ("reverse-http", "http"), ("reverse-unix", "unix"))
                for i in range(self.args.idle):
                    key, mode = modes[i % len(modes)]
                    r, w = await self.connect(mode, ep[key])
                    w.write(b"ready")
                    await w.drain()
                    assert await asyncio.wait_for(r.readexactly(5), 5) == b"ready"
                    connections.append((r, w))
                samples = [{"elapsed_seconds": 0, "processes": {str(p): stats(p) for p in pids}}]
                start = time.monotonic()
                tick = 0
                while time.monotonic() - start < self.args.soak_seconds:
                    await asyncio.sleep(min(self.args.sample_seconds, self.args.soak_seconds - (time.monotonic() - start)))
                    data = struct.pack("!I", tick)
                    async def ping(r, w):
                        w.write(data)
                        await w.drain()
                        assert await asyncio.wait_for(r.readexactly(4), 5) == data
                    await asyncio.gather(*(ping(r, w) for r, w in connections))
                    for key in ("udp", "reverse-udp"):
                        await self.udp(ep[key], 1200, 4)
                    if tick % 6 == 0:
                        await self.batch("socks", ep["socks"], 16)
                        await self.batch("http", ep["http"], 16)
                    samples.append({"elapsed_seconds": round(time.monotonic() - start, 3),
                                    "processes": {str(p): stats(p) for p in pids}})
                    assert all(stats(p).get("rss_kib", 0) < 1024 * 1024 for p in pids), "1 GiB per-process guard exceeded"
                    tick += 1
                    if tick % 12 == 0:
                        self.record(f"soak/{scheme}/progress-{tick}", verified_rounds=tick, latest=samples[-1])
                for _, w in connections:
                    self.owned_writers.discard(w)
                    await close(w)
                connections.clear()
                await asyncio.sleep(2)
                after = {str(p): stats(p) for p in pids}
                self.record(f"soak/{scheme}/keepalive-and-cleanup", baseline=baseline, samples=samples, after_close=after,
                            tunnels=self.args.idle, verified_rounds=tick, duration_seconds=round(time.monotonic() - start, 3),
                            features=[k for k, _ in modes] + ["udp", "reverse-udp"],
                            note="Mixed loopback endurance; duration and resource samples are evidence, not enterprise certification.")
                await self.stop(srv)
                replacement = await self.spawn(f"soak-{scheme}-restart", "server", f"{'ws' if scheme in ('ws', 'http') else 'wts'}://127.0.0.1:{sp}")
                try:
                    await self.ready(sp, replacement)
                    async def recover():
                        recovery_start = time.monotonic()
                        for _ in range(2):
                            try:
                                await asyncio.wait_for(self.exchange("tcp", ep["tcp"]), 12)
                                return {"recovery_seconds": round(time.monotonic() - recovery_start, 3)}
                            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                                await asyncio.sleep(.2)
                        raise TimeoutError("isolated forward tunnel did not recover within 26 seconds")
                    await self.check(f"soak/{scheme}/server-restart-recovery", recover, 28)
                finally:
                    await self.stop(replacement)
            finally:
                for _, w in connections:
                    self.owned_writers.discard(w)
                    await close(w)
                if client:
                    await self.stop(client)
                await self.stop(srv)
        await asyncio.gather(*(self.check(f"soak/{s}/suite", lambda scheme=s: one(scheme), self.args.soak_seconds + 120)
                               for s in self.args.transports.split(",")))

    async def run(self):
        async def echo(r, w):
            self.echo_accepted += 1
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                await close(w)
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0, backlog=1024)
        other = await asyncio.start_server(echo, "127.0.0.1", 0, backlog=1024)
        self.echo_port = echo_server.sockets[0].getsockname()[1]
        self.other_echo_port = other.sockets[0].getsockname()[1]
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(EchoUDP, local_addr=("127.0.0.1", 0))
        self.udp_port = udp.get_extra_info("sockname")[1]
        self.policy = self.out / "qualification-restrictions.yaml"
        self.policy.write_text(f"""restrictions:
  - name: Qualification suite policy
    match: [Any]
    allow:
      # Sections bind more targets on ephemeral ports after this file is written (HTTP proxy
      # origins, half-close peers), so the policy confines the address rather than the port.
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [127.0.0.1/32]
      - !ReverseTunnel
        protocol: [Tcp, Udp, Socks5, HttpProxy, Unix]
        cidr: [127.0.0.1/32]
""")
        binary = self.binary
        metadata = {"started_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "binary": str(binary),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "platform": platform.platform(), "cpus": os.cpu_count(), "worker_threads_per_process": 1,
                    "args": vars(self.args), "fd_limits": resource.getrlimit(resource.RLIMIT_NOFILE),
                    "limitations": ["loopback; shared development host; not maximum capacity or WAN results",
                                    "local duration alone does not establish production capacity or certification",
                                    "privileged TProxy/firewall, ECH/CDN, external DNS, non-Linux platforms not exercised"]}
        (self.out / "metadata.json").write_text(json.dumps(metadata, indent=2))
        try:
            if "protocols" in self.args.sections.split(","):
                await self.check("direct/tcp/control", lambda: self.batch("tcp", self.echo_port, 128, 65536, 4))
                for scheme in self.args.transports.split(","):
                    await self.check(f"{scheme}/suite", lambda s=scheme: self.protocol(s), self.args.hold * 2 + 140)
            if "fleet" in self.args.sections.split(","):
                await self.check("fleet/suite", self.fleet, 45)
            if "security" in self.args.sections.split(","):
                await self.check("security/suite", self.security, 40)
            if "extended" in self.args.sections.split(","):
                await self.check("extended/suite", self.extended, 140)
            if "optimization" in self.args.sections.split(","):
                await self.check("optimization/suite", self.optimize, 90)
            if "isolation" in self.args.sections.split(","):
                await self.check("isolation/suite", self.isolation, 130)
            if "soak" in self.args.sections.split(","):
                await self.soak()
            if "lifecycle" in self.args.sections.split(","):
                await self.check("lifecycle/suite", self.lifecycle, 40)
            if "capacity" in self.args.sections.split(","):
                await self.check("capacity/suite", self.capacity, 1800)
            if "rotation" in self.args.sections.split(","):
                await self.check("rotation/suite", self.certificate_rotation, 100)
        finally:
            for w in self.owned_writers.copy():
                await close(w)
            await asyncio.gather(*(self.stop(p) for p in self.processes))
            echo_server.close()
            other.close()
            await echo_server.wait_closed()
            await other.wait_closed()
            udp.close()
        self.record("coverage/privileged-and-external", "not_run", features=metadata["limitations"][2])
        failures = sum(r["status"] == "fail" for r in self.results)
        print(f"Artifacts: {self.out}; failed checks: {failures}", flush=True)
        return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output")
    parser.add_argument("--transports", default="ws,wss,http,https,wts")
    parser.add_argument("--sections", default="protocols,fleet,security,extended,optimization,isolation,soak,lifecycle,rotation")
    parser.add_argument("--idle", type=int, default=128)
    parser.add_argument("--hold", type=int, default=10)
    parser.add_argument("--devices", type=int, default=64)
    parser.add_argument("--soak-seconds", type=int, default=65)
    parser.add_argument("--sample-seconds", type=int, default=5)
    parser.add_argument("--capacity-levels", default="16,64,128,256")
    args = parser.parse_args()
    if not (1 <= args.idle <= 512 and 1 <= args.hold <= 120 and 1 <= args.devices <= 128):
        parser.error("bounded limits: idle 1..512, hold 1..120 seconds, devices 1..128")
    if not (5 <= args.soak_seconds <= 259200 and 1 <= args.sample_seconds <= 60):
        parser.error("soak 5..259200 seconds; sample interval 1..60 seconds")
    try:
        args.capacity_levels = [int(n) for n in args.capacity_levels.split(",")]
    except ValueError:
        parser.error("capacity levels must be comma-separated integers")
    if not args.capacity_levels or args.capacity_levels != sorted(set(args.capacity_levels)) or not all(1 <= n <= 512 for n in args.capacity_levels):
        parser.error("capacity levels must be increasing unique integers in 1..512")
    if any(s not in ("ws", "wss", "http", "https", "wts") for s in args.transports.split(",")):
        parser.error("unsupported transport")
    if any(s not in ("protocols", "fleet", "security", "extended", "optimization", "isolation", "soak", "lifecycle", "capacity", "rotation") for s in args.sections.split(",")):
        parser.error("unsupported section")
    suite = Suite(args)
    started = time.time()
    exit_code = 1
    state = "failed"
    try:
        exit_code = int(bool(asyncio.run(suite.run())))
        state = "completed" if exit_code == 0 else "failed"
    except KeyboardInterrupt:
        exit_code, state = 130, "interrupted"
    finally:
        results = suite.out / "results.json"
        (suite.out / "completion.json").write_text(json.dumps({
            "state": state, "exit_code": exit_code,
            "started_at_unix": started, "finished_at_unix": time.time(),
            "elapsed_seconds": round(time.time() - started, 3),
            "binary_sha256": hashlib.sha256(suite.binary.read_bytes()).hexdigest(),
            "results_sha256": hashlib.sha256(results.read_bytes()).hexdigest() if results.exists() else None,
        }, indent=2) + "\n")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
