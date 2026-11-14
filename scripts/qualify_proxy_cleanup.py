#!/usr/bin/env python3
"""Linux loopback mTLS checks for proxy/reverse cancellation and directional EOF."""

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time

from qualify import close, port, stats
from qualify_recovery import RecoveryChecks


MODES = ("forward-tcp", "forward-socks", "forward-http", "forward-request",
         "reverse-tcp", "reverse-socks", "reverse-http", "reverse-request")
CASES = ("upload-reset", "download-reset", "half-close", "fin-then-reset")


def reset(writer):
    """Send TCP RST, rather than asyncio abort's potentially graceful TCP FIN."""
    writer.get_extra_info("socket").setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.transport.abort()


async def open_application(mode, endpoint, target, length=0):
    reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
    try:
        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        if mode.endswith("socks"):
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x00"
            writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target))
            await writer.drain()
            reply = await reader.readexactly(4)
            assert reply[:2] == b"\x05\x00", reply
            size = {1: 4, 4: 16}.get(reply[3])
            if size is None:
                size = (await reader.readexactly(1))[0]
            await reader.readexactly(size + 2)
        elif mode.endswith("http"):
            writer.write(f"CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            assert b" 200 " in header.split(b"\r\n", 1)[0], header
        elif mode.endswith("request"):
            writer.write((f"POST http://127.0.0.1:{target}/cleanup HTTP/1.1\r\n"
                          f"Host: localhost\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").encode())
            await writer.drain()
        return reader, writer
    except BaseException:
        await close(writer)
        raise


async def flood(writer, blocked):
    chunk = b"x" * 65536
    sent = 0
    while True:
        writer.write(chunk)
        sent += len(chunk)
        if writer.transport.get_write_buffer_size() > writer.transport.get_write_buffer_limits()[1]:
            blocked.set()
        await writer.drain()
        if sent > 128 * 1024 * 1024:
            raise AssertionError("upload never developed backpressure within 128 MiB")


class CleanupChecks(RecoveryChecks):
    async def sessions(self, stack):
        return await self.suite.api(stack["management"], "/api/v1/sessions")

    @staticmethod
    def active(sessions):
        return [s for s in sessions if s["kind"] == "tunnel" and s["state"] != "pending"]

    async def settled(self, stack, reverse=False, active=0, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            health = await self.suite.api(stack["management"], "/healthz")
            sessions = await self.sessions(stack)
            if len(self.active(sessions)) == active and health["active_tunnels"] <= active + int(reverse):
                return health
            await asyncio.sleep(.025)
        raise AssertionError(f"tunnel resources held: health={health}; sessions={sessions}")

    async def active_tunnel(self, stack):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            sessions = await self.sessions(stack)
            if len(self.active(sessions)) == 1:
                return self.active(sessions)[0]["session_id"]
            await asyncio.sleep(.01)
        raise AssertionError(f"test never established exactly one active tunnel: {sessions}")

    async def start_application(self, stack, scheme, mode, target):
        endpoint = port()
        reverse = mode.startswith("reverse")
        protocol = "socks5" if mode.endswith("socks") else "http" if mode.endswith(("http", "request")) else "tcp"
        destination = f":127.0.0.1:{target}" if protocol == "tcp" else ""
        await self.client(stack, scheme, specs=["-R" if reverse else "-L",
            f"{protocol}://127.0.0.1:{endpoint}{destination}"],
            extra_args=("--connection-min-idle", "0"))
        await self.passive_listener(endpoint, stack["clients"][-1])
        return endpoint

    @asynccontextmanager
    async def origin(self, mode, behavior):
        tasks, writers = set(), set()
        accepted = asyncio.Queue()
        release = asyncio.Event()
        blocked = asyncio.Event()
        sending = []
        errors = []
        reply = b"reply:" + os.urandom(256 * 1024 + 3)
        request = os.urandom(128 * 1024 + 17)

        async def handle(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            writers.add(writer)
            writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            accepted.put_nowait(writer)
            try:
                if behavior == "upload-reset":
                    await release.wait()
                elif behavior == "fin-then-reset":
                    writer.write_eof()
                    await release.wait()
                elif behavior == "download-reset":
                    if mode.endswith("request"):
                        await reader.readuntil(b"\r\n\r\n")
                        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\nConnection: close\r\n\r\n")
                    sending.append(asyncio.current_task())
                    await flood(writer, blocked)
                else:
                    if mode.endswith("request"):
                        header = await reader.readuntil(b"\r\n\r\n")
                        lengths = [int(x.split(b":", 1)[1]) for x in header.split(b"\r\n") if x.lower().startswith(b"content-length:")]
                        assert lengths == [len(request)], header
                        received = await reader.readexactly(len(request))
                    else:
                        received = await reader.read()
                    assert received == request, (len(received), len(request))
                    if mode.endswith("request"):
                        writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(reply)}\r\nConnection: close\r\n\r\n".encode())
                    writer.write(reply)
                    await writer.drain()
            except (OSError, asyncio.IncompleteReadError) as error:
                if behavior == "half-close":
                    errors.append(str(error))
            except AssertionError as error:
                errors.append(str(error))
            finally:
                writers.discard(writer)
                tasks.discard(task)
                await close(writer)

        server = await asyncio.start_server(handle, "127.0.0.1", self.unused_port)
        try:
            yield {"accepted": accepted, "blocked": blocked, "sending": sending,
                   "reply": reply, "request": request, "errors": errors}
        finally:
            server.close()
            release.set()
            for writer in tuple(writers):
                writer.transport.abort()
            pending = tuple(tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await server.wait_closed()

    async def case(self, scheme, mode, behavior):
        reverse = mode.startswith("reverse")
        async with self.stack(f"{scheme}-{mode}-{behavior}", max_tunnels=2 if reverse else 1) as stack:
            endpoint = await self.start_application(stack, scheme, mode, self.unused_port)
            before = {"server": stats(stack["process"].pid), "client": stats(stack["clients"][-1].pid)}
            timings = []
            for cycle in range(self.suite.args.cycles):
                async with self.origin(mode, behavior) as target:
                    reader, writer = await asyncio.wait_for(open_application(mode, endpoint, self.unused_port,
                        len(target["request"]) if behavior == "half-close" else 1073741824 if behavior == "upload-reset" else 0), 8)
                    producer = None
                    try:
                        remote = await asyncio.wait_for(target["accepted"].get(), 5)
                        session = await self.active_tunnel(stack)
                        if behavior == "half-close":
                            writer.write(target["request"])
                            await writer.drain()
                            writer.write_eof()
                            if mode.endswith("request"):
                                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 8)
                                assert b" 200 " in header.split(b"\r\n", 1)[0], header
                            assert await asyncio.wait_for(reader.readexactly(len(target["reply"])), 8) == target["reply"]
                            assert await asyncio.wait_for(reader.read(), 8) == b""
                            assert not target["errors"], target["errors"]
                        else:
                            if behavior == "fin-then-reset":
                                assert await asyncio.wait_for(reader.read(1), 5) == b""
                            if behavior in ("upload-reset", "fin-then-reset"):
                                blocked = asyncio.Event()
                                producer = asyncio.create_task(flood(writer, blocked))
                                await asyncio.wait_for(blocked.wait(), 5)
                            else:
                                await asyncio.wait_for(target["blocked"].wait(), 5)
                            # Allow bounded transport buffers to fill before injecting the reset.
                            await asyncio.sleep(.2)
                            assert not producer or not producer.done(), "the upload ended before reset injection"
                            reset(remote if behavior == "download-reset" else writer)
                        started = time.monotonic()
                        await self.settled(stack, reverse)
                        assert session not in {s["session_id"] for s in await self.sessions(stack)}, session
                        timings.append(round((time.monotonic() - started) * 1000, 3))
                    finally:
                        if producer:
                            producer.cancel()
                            await asyncio.gather(producer, return_exceptions=True)
                        await close(writer)
            after = {"server": stats(stack["process"].pid), "client": stats(stack["clients"][-1].pid)}
            for role in before:
                assert after[role]["fds"] <= before[role]["fds"] + 6, (role, before, after)
                assert after[role]["threads"] <= before[role]["threads"] + 2, (role, before, after)
            return {"cycles": self.suite.args.cycles, "max_tunnels": 2 if reverse else 1,
                    "idle_reverse_request_preserved": reverse, "quota_slot_reused": True,
                    "before": before, "after": after, "cleanup_ms": timings}

    async def run(self):
        started = time.time()
        state, exit_code = "failed", 1
        try:
            await self.prepare()
            for scheme in self.suite.args.transports.split(","):
                for mode in self.suite.args.modes.split(","):
                    for behavior in self.suite.args.cases.split(","):
                        if behavior == "fin-then-reset" and mode.endswith("request"):
                            continue  # HTTP message completion is not a directional stream FIN.
                        await self.suite.check(f"cleanup/{scheme}/{mode}/{behavior}",
                            lambda s=scheme, m=mode, b=behavior: self.case(s, m, b),
                            12 + self.suite.args.cycles * 22)
            assert self.suite.results, "no applicable cases selected"
            exit_code = int(any(r["status"] != "pass" for r in self.suite.results))
            state = "completed" if exit_code == 0 else "failed"
            return exit_code
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            if hasattr(self, "target"):
                self.target.close()
                await self.target.wait_closed()
            if hasattr(self, "udp"):
                self.udp.close()
            results = self.suite.out / "results.json"
            (self.suite.out / "completion.json").write_text(json.dumps({
                "state": state, "exit_code": exit_code, "started_at_unix": started,
                "finished_at_unix": time.time(), "cycles": self.suite.args.cycles,
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "results_sha256": hashlib.sha256(results.read_bytes()).hexdigest() if results.exists() else None,
                "modes": self.suite.args.modes.split(","), "cases": self.suite.args.cases.split(","),
                "scope": "Linux loopback verified mTLS; one active tunnel plus a pending request for reverse; no WAN claim"
            }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    parser.add_argument("--transports", default="wss,https,wts")
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--cycles", type=int, default=2)
    args = parser.parse_args()
    for value, allowed in ((args.transports, ("wss", "https", "wts")), (args.modes, MODES), (args.cases, CASES)):
        if not value or any(x not in allowed for x in value.split(",")):
            parser.error(f"unsupported selection {value!r}; choose from {allowed}")
    if not 1 <= args.cycles <= 20:
        parser.error("cycles must be between 1 and 20")
    if args.cases == "fin-then-reset" and all(m.endswith("request") for m in args.modes.split(",")):
        parser.error("fin-then-reset requires a stream mode")
    if not Path("/proc/net/tcp").exists():
        parser.error("resource checks require Linux /proc")
    raise SystemExit(asyncio.run(CleanupChecks(args).run()))


if __name__ == "__main__":
    main()
