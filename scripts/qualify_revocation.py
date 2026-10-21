#!/usr/bin/env python3
"""Bounded loopback checks for live mTLS certificate/device denial and resource cleanup."""

import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import socket
import ssl
import time

from qualify import close, port
from qualify_quotas import QuotaChecks


class RevocationChecks(QuotaChecks):
    def write_policy(self, stack, devices=(), certificates=(), raw=None):
        policy = stack["revocations"]
        temporary = policy.with_suffix(".new")
        temporary.write_text(raw if raw is not None else json.dumps({
            "version": 1, "blocked_devices": list(devices), "blocked_cert_sha256": list(certificates)}))
        temporary.replace(policy)

    @asynccontextmanager
    async def server(self, label, limits=None):
        self.serial += 1
        prefix = f"{self.serial}-{label}"
        sp, mp = port(), port()
        stack = {"port": sp, "management": mp, "prefix": prefix, "clients": [], "writers": [],
                 "revocations": self.suite.out / f"{prefix}-revocations.yaml"}
        self.write_policy(stack)
        options = []
        if limits:
            quota = self.suite.out / f"{prefix}-quotas.yaml"
            quota.write_text(json.dumps({"version": 1, "default": limits}))
            options = ["--device-quota-config", str(quota)]
        process = await self.suite.spawn(prefix, "server", f"wts://127.0.0.1:{sp}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(self.policy),
            "--device-revocation-config", str(stack["revocations"]), *options,
            "--websocket-ping-frequency", "1s", "--remote-to-local-server-idle-timeout", "1h", log_level="INFO")
        try:
            await self.suite.ready(sp, process)
            yield stack
        finally:
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await asyncio.gather(*(self.suite.stop(client) for client in stack["clients"]))
            await self.suite.stop(process)

    async def connect_held(self, stack, scheme, identity="a"):
        endpoint, _ = await self.client(stack, scheme, identity)
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        stack["writers"].append(writer)
        await self.exchange_held((reader, writer))
        return endpoint, (reader, writer)

    @staticmethod
    async def exchange_held(pair):
        reader, writer = pair
        writer.write(b"still-open")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(10), 3) == b"still-open"

    @staticmethod
    async def disconnected(pair):
        reader, _ = pair
        try:
            assert await asyncio.wait_for(reader.read(1), 5) == b""
        except ConnectionError:
            pass

    def fingerprint(self, identity="a"):
        pem = (self.certs / f"{identity}.pem").read_text()
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

    @staticmethod
    def listening(endpoint):
        return any(int(row.split()[1].rsplit(":", 1)[1], 16) == endpoint and row.split()[3] == "0A"
                   for row in Path("/proc/net/tcp").read_text().splitlines()[1:])

    async def applied(self, stack, previous):
        for _ in range(150):
            if self.log(stack).count("Applied device revocation policy") > previous:
                return
            await asyncio.sleep(0.02)
        raise AssertionError("policy update was not applied within 3 seconds")

    async def update(self, stack, **kwargs):
        previous = self.log(stack).count("Applied device revocation policy")
        self.write_policy(stack, **kwargs)
        await self.applied(stack, previous)

    async def fingerprint_rotation(self):
        async with self.server("fingerprint") as stack:
            old, rotated, others = [], [], []
            for scheme in ("wss", "https", "wts"):
                old.append(await self.connect_held(stack, scheme))
                rotated.append((await self.connect_held(stack, scheme, "rotated-a"))[1])
                others.append((await self.connect_held(stack, scheme, "b"))[1])
            started = time.monotonic()
            await self.update(stack, certificates=[self.fingerprint().upper()])
            await asyncio.gather(*(self.disconnected(pair) for _, pair in old))
            for pair in rotated + others:
                await self.exchange_held(pair)
            accepted = self.accepted
            for endpoint, _ in old:
                await self.denied(stack, endpoint)
            assert self.accepted == accepted, "revoked certificate opened a target"
            await self.update(stack)
            for endpoint, _ in old:
                await self.held(stack, endpoint)
            return {"transports": 3, "leaf_only": True, "rotated_same_cn_survives": True,
                    "separate_device_survives": True, "reconnect_denied_before_target": True,
                    "seconds_including_update_and_checks": round(time.monotonic() - started, 3)}

    async def device_identity(self):
        async with self.server("identity") as stack:
            devices = [await self.connect_held(stack, scheme, identity)
                       for scheme in ("wss", "https", "wts") for identity in ("a", "rotated-a")]
            b = (await self.connect_held(stack, "wts", "b"))[1]
            await self.update(stack, devices=["spoofed-label", "DEVICE-A"])
            for _, pair in devices:
                await self.exchange_held(pair)
            await self.update(stack, devices=["device-a"])
            await asyncio.gather(*(self.disconnected(pair) for _, pair in devices))
            await self.exchange_held(b)
            for endpoint, _ in devices:
                await self.denied(stack, endpoint)
            return {"verified_cn_only": True, "case_sensitive": True, "all_keys_closed": 6, "other_device_survives": True}

    async def idle(self):
        async with self.server("idle") as stack:
            reader, writer = await asyncio.open_connection("127.0.0.1", stack["port"], ssl=self.context("a"))
            stack["writers"].append(writer)
            # Ensure the authenticated session has reached the HTTP idle wait.
            await asyncio.sleep(0.1)
            await self.update(stack, devices=["device-a"])
            await self.disconnected((reader, writer))
            return {"idle_tls_connection_closed": True}

    async def reverse(self, scheme):
        async with self.server(f"reverse-{scheme}") as stack:
            fixed = port()
            await self.client(stack, scheme, specs=["-R", f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"])
            for _ in range(150):
                if self.listening(fixed):
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("reverse listener not allocated")
            reader, writer = await asyncio.open_connection("127.0.0.1", fixed)
            stack["writers"].append(writer)
            pair = reader, writer
            await self.exchange_held(pair)
            await self.update(stack, certificates=[self.fingerprint()])
            await self.disconnected(pair)
            for _ in range(150):
                if not self.listening(fixed):
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("revoked certificate retained its reverse listener")
            try:
                _, probe = await asyncio.open_connection("127.0.0.1", fixed)
            except ConnectionRefusedError:
                pass
            else:
                await close(probe)
                raise AssertionError("revoked reverse endpoint still accepts connections")
            endpoint, _ = await self.client(stack, "wts", "b")
            await self.held(stack, endpoint)
            return {"transport": scheme, "active_forward_closed": True, "listener_closed": True,
                    "quotas_disabled": True, "configured_idle_timeout_seconds": 3600}

    async def unavailable(self, deletion):
        async with self.server("unavailable") as stack:
            held = [await self.connect_held(stack, scheme) for scheme in ("wss", "https", "wts")]
            previous = self.log(stack).count("Applied device revocation policy")
            if deletion:
                stack["revocations"].unlink()
                await self.applied(stack, previous)
            else:
                await self.update(stack, raw="version: 1\nblocked_devcies: [device-a]\n")
            await asyncio.gather(*(self.disconnected(pair) for _, pair in held))
            for endpoint, _ in held:
                await self.denied(stack, endpoint)
            await self.update(stack)
            for endpoint, _ in held:
                await self.held(stack, endpoint)
            return {"missing_file": deletion, "fail_closed_all_transports": True, "valid_policy_recovers": True}

    async def shaping_cancellation(self):
        async with self.server("shaping", {"max_sessions": 1, "max_tunnels": 1,
                                            "upload_bytes_per_second": 1}) as stack:
            endpoint, process = await self.client(stack, "wts")
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
            stack["writers"].append(writer)
            writer.write(b"x" * 131072)
            await writer.drain()
            # The second full record must wait for bandwidth credit.
            assert await asyncio.wait_for(reader.read(65536), 3)
            await self.update(stack, devices=["device-a"])
            # Drain already-delivered bytes; none can wait indefinitely on shaping after revocation.
            try:
                await asyncio.wait_for(reader.read(), 5)
            except ConnectionError:
                pass
            await self.suite.stop(process)
            await self.update(stack)
            endpoint, _ = await self.client(stack, "wts", "rotated-a")
            # Initial bandwidth may remain spent; only verify admission and then revoke to avoid a long wait.
            before = self.accepted
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
            stack["writers"].append(writer)
            writer.write(b"new")
            await writer.drain()
            for _ in range(100):
                if self.accepted > before:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("revoked shaping work retained its session/tunnel quota")
            return {"bandwidth_wait_cancelled": True, "session_and_tunnel_permits_released": True}

    def resume_exchange(self, endpoint, context, session=None):
        with socket.create_connection(("127.0.0.1", endpoint), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname="localhost", session=session) as secure:
                secure.sendall(b"GET /device-a/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                body = b""
                try:
                    while data := secure.recv(4096):
                        body += data
                except (ConnectionError, ssl.SSLError):
                    pass
                return body, secure.session, secure.session_reused

    async def resumption(self):
        async with self.server("resumption") as stack:
            context = self.context("a")
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            body, session, _ = await asyncio.to_thread(self.resume_exchange, stack["port"], context)
            assert b"400 Bad Request" in body
            body, session, reused = await asyncio.to_thread(self.resume_exchange, stack["port"], context, session)
            assert reused and b"400 Bad Request" in body, "baseline TLS session resumption not exercised"
            await self.update(stack, certificates=[self.fingerprint()])
            body, _, reused = await asyncio.to_thread(self.resume_exchange, stack["port"], context, session)
            assert reused and not body, "resumed session bypassed current certificate denial"
            return {"tls12_resumption_observed": True, "resumed_revoked_certificate_denied": True}

    async def invalid_startup(self):
        policy = self.suite.out / "startup-policy.yaml"
        for label, uri, content, ca in (
            ("cleartext", "ws", "version: 1", True),
            ("invalid", "wss", "version: 2", True),
            ("no-ca", "wss", "version: 1", False),
        ):
            endpoint = port()
            policy.write_text(content)
            options = ["--tls-client-ca-certs", str(self.certs / "ca.pem")] if ca else []
            process = await self.suite.spawn(f"startup-{label}", "server", f"{uri}://127.0.0.1:{endpoint}",
                "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--device-revocation-config", str(policy), *options)
            assert await asyncio.wait_for(process.wait(), 5) != 0
            assert not self.bound(endpoint)
        return {"cleartext_invalid_policy_and_missing_client_ca_rejected": True}

    async def run(self):
        await self.prepare()
        try:
            cases = [("certificate-and-key-rotation", self.fingerprint_rotation),
                     ("device-cn-and-labels", self.device_identity), ("idle-tls", self.idle),
                     *[(f"reverse-{scheme}", lambda s=scheme: self.reverse(s)) for scheme in ("wss", "https", "wts")],
                     ("invalid-policy", lambda: self.unavailable(False)),
                     ("missing-policy", lambda: self.unavailable(True)),
                     ("shaping-cancellation-and-quota-release", self.shaping_cancellation),
                     ("tls-resumption", self.resumption), ("startup-validation", self.invalid_startup)]
            for name, case in cases:
                await self.suite.check(f"revocation/{name}", case, 45)
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in self.suite.processes))
            self.target.close()
            await self.target.wait_closed()
            self.udp.close()
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "synthetic loopback mTLS; local denylist, not X.509 CRL/OCSP or distributed revocation",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(RevocationChecks(parser.parse_args()).run())))
