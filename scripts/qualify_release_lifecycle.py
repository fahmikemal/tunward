#!/usr/bin/env python3
"""Disposable Linux install/upgrade/rollback rehearsal with two supplied binaries.

Verify downloaded archives/provenance before invoking this runner. It installs
only below a new private output directory and never activates a host service.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import sys
import time
import urllib.request

from qualify_runtime import RuntimeChecks, close, port, udp_exchange


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseLifecycle(RuntimeChecks):
    def __init__(self, args):
        super().__init__(args)
        self.candidate = self.binary
        self.previous = self.out / "previous-input"
        shutil.copy2(args.previous_binary, self.previous)
        self.hashes = {"previous": digest(self.previous), "candidate": digest(self.candidate)}
        if self.hashes["previous"] == self.hashes["candidate"]:
            raise ValueError("provide different binaries to qualify an actual upgrade and rollback")
        self.started = time.time()
        self.runner_hash = digest(Path(__file__))
        self.helpers_hash = digest(Path(__file__).with_name("qualify_runtime.py"))
        self.prefix = self.out / "installation"
        self.current = self.prefix / "current"
        self.database = self.out / "inventory.sqlite3"
        self.server = None
        self.activations = []

    async def stop(self, process):
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

    async def spawn_at(self, binary, label, *args, **kwargs):
        saved, self.binary = self.binary, binary
        try:
            return await self.spawn(label, *args, **kwargs)
        finally:
            self.binary = saved

    def activate(self, name):
        temporary = self.prefix / "next"
        temporary.symlink_to(Path("releases") / name, target_is_directory=True)
        os.replace(temporary, self.current)
        assert digest(self.current / "tunward") == self.hashes[name]
        self.activations.append({"slot": name, "binary_sha256": self.hashes[name]})

    async def api(self, path):
        def fetch():
            # This endpoint is the disposable loopback management listener, never a proxy.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{self.management}{path}", timeout=5) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                return json.load(response)
        return await asyncio.to_thread(fetch)

    def server_arguments(self, policy=None):
        return ("server", "--tls-certificate", self.certs / "server.pem",
                "--tls-private-key", self.certs / "server.key", "--tls-client-ca-certs", self.certs / "ca.pem",
                "--restrict-config", policy or self.policy, "--fleet-inventory", self.database,
                "--device-revocation-config", self.revocations, "--management-api", f"127.0.0.1:{self.management}",
                "--websocket-ping-frequency", "1s", "--remote-to-local-server-idle-timeout", "3s",
                f"wts://127.0.0.1:{self.server_port}")

    async def validate(self, binary, policy=None):
        env = os.environ.copy()
        env["NO_COLOR"] = "true"
        process = await asyncio.create_subprocess_exec(str(binary), *map(str, self.server_arguments(policy)),
                "--test-config", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
        self.processes.append(process)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        finally:
            await self.stop(process)
        return process.returncode, (stdout + stderr).decode(errors="replace")

    async def require_valid(self, binary):
        status, output = await self.validate(binary)
        assert status == 0, f"candidate preflight exited {status}: {output}"

    async def start_server(self, phase):
        self.server = await self.spawn_at(self.current / "tunward", phase, *self.server_arguments(), log_level="INFO")
        await self.ready(self.management, self.server)
        actual = digest(Path(f"/proc/{self.server.pid}/exe"))
        assert actual == digest(self.current / "tunward"), "running executable differs from activated binary"
        return actual

    async def clients(self, binary, phase, identities=("client", "control")):
        items = []
        for identity in identities:
            for scheme in ("wss", "https", "wts"):
                forward, reverse, datagram = port(), port(), port()
                process = await self.spawn_at(binary, f"{phase}-{identity}-{scheme}", "client",
                    "--tls-verify-certificate", "--tls-certificate", self.certs / f"{identity}.pem",
                    "--tls-private-key", self.certs / f"{identity}.key", "--connection-retry-max-backoff", "1s",
                    "--reverse-tunnel-connection-retry-max-backoff", "1s", "--websocket-ping-frequency", "1s",
                    "-L", f"tcp://127.0.0.1:{forward}:127.0.0.1:{self.target_port}",
                    "-R", f"tcp://127.0.0.1:{reverse}:127.0.0.1:{self.target_port}",
                    "-L", f"udp://127.0.0.1:{datagram}:127.0.0.1:{self.udp_port}",
                    f"{scheme}://127.0.0.1:{self.server_port}")
                await self.ready(forward, process)
                items.append({"identity": identity, "scheme": scheme, "forward": forward,
                              "reverse": reverse, "udp": datagram, "process": process})
        return items

    async def traffic(self, phase, clients, binary_hash):
        for item in clients:
            attempts = 0
            deadline = time.monotonic() + 20
            while True:
                attempts += 1
                try:
                    await self.exchange(item["forward"])
                    await self.exchange(item["reverse"])
                    with socket.socket(type=socket.SOCK_DGRAM) as sock:
                        sock.setblocking(False)
                        sock.connect(("127.0.0.1", item["udp"]))
                        size = await udp_exchange(sock)
                    break
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    if time.monotonic() >= deadline:
                        raise
                    assert item["process"].returncode is None, "client exited during restart recovery"
                    await asyncio.sleep(0.1)
            self.record(f"deployment/{phase}/{item['identity']}/{item['scheme']}",
                        forward_tcp=True, reverse_tcp=True, udp_bytes=size,
                        client_sha256=binary_hash, attempts=attempts, verified_mtls=True)
        health = await self.api("/healthz")
        assert health["inventory_enabled"] and health["inventory_healthy"] is True, health

    async def denied(self, phase, clients):
        for item in clients:
            reader, writer = await asyncio.open_connection("127.0.0.1", item["forward"])
            try:
                writer.write(b"revoked-device-must-not-pass")
                await writer.drain()
                try:
                    assert await asyncio.wait_for(reader.read(1), 8) == b"", "revoked device forwarded data"
                except ConnectionError:
                    pass
            finally:
                await close(writer)
            self.record(f"deployment/{phase}/revoked/{item['scheme']}", revoked_device_denied=True)

    async def inventory(self):
        return {row["id"]: row for row in (await self.api("/api/v1/devices"))["devices"]}

    def schema(self):
        with sqlite3.connect(self.database) as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            return db.execute("PRAGMA user_version").fetchone()[0]

    async def run(self):
        target = udp = None
        state, exit_code = "failed", 1
        try:
            await self.prepare()
            await self.command("openssl", "req", "-config", self.certs / "openssl.cnf", "-new", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=release-control",
                "-keyout", self.certs / "control.key", "-out", self.certs / "control.csr")
            await self.command("openssl", "x509", "-req", "-in", self.certs / "control.csr", "-CA", self.certs / "ca.pem",
                "-CAkey", self.certs / "ca.key", "-set_serial", "103", "-days", "4",
                "-extfile", self.certs / "client.ext", "-out", self.certs / "control.pem")
            (self.certs / "control.key").chmod(0o600)
            async def echo(reader, writer):
                try:
                    while data := await reader.read(65536):
                        writer.write(data)
                        await writer.drain()
                finally:
                    await close(writer)
            target = await asyncio.start_server(echo, "127.0.0.1", 0)
            self.target_port = target.sockets[0].getsockname()[1]
            class UDP(asyncio.DatagramProtocol):
                def connection_made(self, transport): self.transport = transport
                def datagram_received(self, data, peer): self.transport.sendto(data, peer)
            udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
            self.udp_port = udp.get_extra_info("sockname")[1]
            self.server_port, self.management = port(), port()
            self.policy = self.out / "restrictions.yaml"
            self.policy.write_text(f"restrictions:\n - name: Release rehearsal\n   match: [Any]\n   allow:\n"
                f"    - !Tunnel\n      protocol: [Tcp, Udp]\n      port: ['{self.target_port}', '{self.udp_port}']\n      cidr: [127.0.0.1/32]\n"
                "    - !ReverseTunnel\n      protocol: [Tcp]\n      cidr: [127.0.0.1/32]\n")
            self.revocations = self.out / "revocations.yaml"
            self.revocations.write_text("version: 1\nblocked_devices: []\nblocked_cert_sha256: []\n")
            for name, binary in (("previous", self.previous), ("candidate", self.candidate)):
                directory = self.prefix / "releases" / name
                directory.mkdir(parents=True)
                shutil.copy2(binary, directory / "tunward")
                (directory / "tunward").chmod(0o555)
            previous, candidate = (self.prefix / "releases" / n / "tunward" for n in ("previous", "candidate"))
            self.activate("previous")
            await self.require_valid(previous)
            await self.start_server("installed-previous")
            old_clients = await self.clients(previous, "old-client")
            await self.traffic("install", old_clients, self.hashes["previous"])
            before = await self.inventory()
            assert set(before) == {"runtime-device", "release-control"}, before
            invalid = self.out / "invalid-restrictions.yaml"
            invalid.write_text("restrictions: invalid\n")
            status, output = await self.validate(candidate, invalid)
            assert status != 0, output
            assert self.current.resolve().name == "previous"
            await self.traffic("rejected-candidate", old_clients, self.hashes["previous"])
            self.record("deployment/invalid-candidate-retains-active-installation", exit_code=status)
            await self.require_valid(candidate)
            await self.stop(self.server)
            previous_schema = self.schema()
            with sqlite3.connect(self.database) as source, sqlite3.connect(self.out / "inventory-backup.sqlite3") as backup:
                source.backup(backup)
                assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            self.activate("candidate")
            await self.start_server("upgraded-candidate")
            await self.traffic("upgrade-old-client", old_clients, self.hashes["previous"])
            fresh = await self.clients(candidate, "new-client", ("control",))
            await self.traffic("upgrade-new-client", fresh, self.hashes["candidate"])
            for item in fresh: await self.stop(item["process"])
            current = await self.inventory()
            assert all(current[k]["first_seen_at"] == before[k]["first_seen_at"] for k in before)
            assert all(current[k]["observed_connections"] > before[k]["observed_connections"] for k in before)
            server_log = self.out / self.process_logs[self.server.pid]
            applied = server_log.read_text().count("Applied device revocation policy")
            temporary = self.out / "revocations.next"
            temporary.write_text("version: 1\nblocked_devices: [runtime-device]\nblocked_cert_sha256: []\n")
            os.replace(temporary, self.revocations)
            for _ in range(200):
                if server_log.read_text().count("Applied device revocation policy") > applied: break
                await asyncio.sleep(0.025)
            else: raise AssertionError("revocation policy was not applied")
            revoked = [item for item in old_clients if item["identity"] == "client"]
            control = [item for item in old_clients if item["identity"] == "control"]
            await self.denied("before-rollback", revoked)
            revocation_hash = digest(self.revocations)
            await self.stop(self.server)
            assert self.schema() == previous_schema, "schema changed: direct downgrade is not qualified"
            await self.require_valid(previous)
            self.activate("previous")
            await self.start_server("rolled-back-previous")
            await self.traffic("rollback-old-client", control, self.hashes["previous"])
            await self.denied("after-rollback", revoked)
            fresh = await self.clients(candidate, "rollback-new-client", ("control",))
            await self.traffic("rollback-new-client", fresh, self.hashes["candidate"])
            after = await self.inventory()
            assert all(after[k]["first_seen_at"] == before[k]["first_seen_at"] for k in before)
            assert all(after[k]["observed_connections"] >= current[k]["observed_connections"] for k in before)
            assert digest(self.revocations) == revocation_hash
            assert digest(Path(__file__)) == self.runner_hash, "runner changed during qualification"
            assert digest(Path(__file__).with_name("qualify_runtime.py")) == self.helpers_hash
            self.record("deployment/persistent-state-and-revocation", inventory_schema=previous_schema,
                devices_preserved=sorted(before), first_seen_preserved=True, revocation_preserved=True,
                inventory_backup_sha256=digest(self.out / "inventory-backup.sqlite3"))
            state, exit_code = "completed", 0
        except Exception as error:
            self.record("deployment/suite", "fail", error=f"{type(error).__name__}: {error}")
        finally:
            for process in reversed(self.processes): await self.stop(process)
            if target is not None:
                target.close()
                await target.wait_closed()
            if udp is not None: udp.close()
            metadata = {"state": state, "exit_code": exit_code, "started_at_unix": self.started,
                "finished_at_unix": time.time(), "binary_sha256": self.hashes, "activations": self.activations,
                "runner_sha256": self.runner_hash, "runtime_helpers_sha256": self.helpers_hash,
                "results_sha256": digest(self.out / "results.json"),
                "scope": "disposable Linux loopback; supplied binaries, protocol-v2 compatibility, same-schema inventory and revocation; not host systemd, WAN or cross-schema downgrade"}
            (self.out / "completion.json").write_text(json.dumps(metadata, indent=2) + "\n")
        return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--previous-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this rehearsal requires Linux /proc and atomic directory symlinks")
    raise SystemExit(asyncio.run(ReleaseLifecycle(args).run()))
