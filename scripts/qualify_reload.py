#!/usr/bin/env python3
"""Bounded Unix reload checks with live loopback traffic and disposable mTLS identities."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import ssl
import tempfile
import traceback

from qualify_runtime import RuntimeChecks, close, port, udp_exchange


class ReloadChecks(RuntimeChecks):
    def replace(self, path, data):
        temporary = path.with_suffix(path.suffix + ".candidate")
        temporary.write_bytes(data.encode() if isinstance(data, str) else data)
        temporary.chmod(0o600)
        temporary.replace(path)

    def policies(self):
        rules = f"""restrictions:
 - name: forward
   match: [Any]
   allow:
    - !Tunnel
      protocol: [Tcp, Udp]
      port: ['{self.target_port}', '{self.udp_port}']
      cidr: [127.0.0.1/32]
 - name: reverse
   match: [Any]
   allow:
    - !ReverseTunnel
      protocol: [Tcp]
      cidr: [127.0.0.1/32]
"""
        if self.extra_grant:
            rules += f""" - name: extra
   match: [Any]
   allow:
    - !Tunnel
      protocol: [Tcp]
      port: ['{self.extra_port}']
      cidr: [127.0.0.1/32]
"""
        self.replace(self.policy, rules)
        self.replace(self.tenant_file, json.dumps(self.tenants))
        self.replace(self.quota_file, json.dumps({"version": 1, "default": self.limits}))

    async def issue(self, name, identity, purpose, ca="ca", serial=200):
        await self.command("openssl", "req", "-config", self.certs / "openssl.cnf", "-new", "-newkey", "ec",
                           "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={identity}",
                           "-keyout", self.certs / f"{name}.key", "-out", self.certs / f"{name}.csr")
        await self.command("openssl", "x509", "-req", "-in", self.certs / f"{name}.csr", "-CA", self.certs / f"{ca}.pem",
                           "-CAkey", self.certs / f"{ca}.key", "-set_serial", serial, "-days", 4,
                           "-extfile", self.certs / f"{purpose}.ext", "-out", self.certs / f"{name}.pem")
        (self.certs / f"{name}.key").chmod(0o600)

    async def echo(self, reader, writer):
        self.accepted += 1
        try:
            while payload := await reader.read(65536):
                writer.write(payload)
                await writer.drain()
        except OSError:
            pass
        finally:
            await close(writer)

    async def setup(self):
        await self.prepare()
        await self.issue("other", "other-device", "client", serial=201)
        await self.command("openssl", "req", "-config", self.certs / "openssl.cnf", "-extensions", "ca", "-x509",
                           "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", 4,
                           "-subj", "/CN=Reload Replacement CA", "-keyout", self.certs / "replacement-ca.key",
                           "-out", self.certs / "replacement-ca.pem")
        (self.certs / "replacement-ca.key").chmod(0o600)
        await self.issue("renewed-server", "localhost", "server", ca="replacement-ca", serial=202)
        await self.issue("renewed-client", "runtime-device", "client", ca="replacement-ca", serial=203)
        self.old_ca = (self.certs / "ca.pem").read_bytes()
        self.old_cert = (self.certs / "server.pem").read_bytes()
        self.old_key = (self.certs / "server.key").read_bytes()
        self.client_ca = self.certs / "client-ca.pem"
        self.replace(self.client_ca, self.old_ca)
        self.accepted, self.serial, self.generation = 0, 0, 1
        self.held_streams, self.udp_sockets, self.targets = [], [], []
        for _ in range(2):
            self.targets.append(await asyncio.start_server(self.echo, "127.0.0.1", 0))
        self.target_port, self.extra_port = [target.sockets[0].getsockname()[1] for target in self.targets]
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, peer):
                self.transport.sendto(data, peer)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp.get_extra_info("sockname")[1]
        self.policy, self.tenant_file, self.quota_file = [self.out / name for name in ("restrictions.yaml", "tenants.json", "quotas.json")]
        self.revocation_file = self.out / "revocations.json"
        self.replace(self.revocation_file, '{"version":1,"blocked_devices":[]}')
        self.extra_grant = False
        self.reverse_ports = [port() for _ in range(3)]
        self.tenants = {"version": 1, "roles": {"forwarder": ["forward_tcp", "forward_udp"], "reverse": ["reverse_tcp"]},
            "tenants": {"alpha": {"restrictions": ["forward", "reverse"], "reverse_bindings": [
                {"address": "127.0.0.1", "ports": list(map(str, self.reverse_ports))}]},
                "beta": {"restrictions": ["forward"]}},
            "devices": {"runtime-device": {"tenant": "alpha", "roles": ["forwarder", "reverse"]},
                        "other-device": {"tenant": "beta", "roles": ["forwarder"]}}}
        self.limits = {"max_sessions": 128, "max_tunnels": 64, "requests_per_second": 100,
                       "request_burst": 200, "upload_bytes_per_second": 4194304,
                       "download_bytes_per_second": 4194304, "bandwidth_burst_bytes": 65536}
        self.policies()
        self.server_port, self.management = port(), port()
        self.server = await self.spawn("server", "server", "--reload-socket", self.control,
            "--tls-certificate", self.certs / "server.pem", "--tls-private-key", self.certs / "server.key",
            "--tls-client-ca-certs", self.client_ca, "--restrict-config", self.policy,
            "--tenant-config", self.tenant_file, "--device-quota-config", self.quota_file,
            "--device-revocation-config", self.revocation_file,
            "--management-api", f"127.0.0.1:{self.management}", "--websocket-ping-frequency", "1s",
            f"wts://127.0.0.1:{self.server_port}", log_level="INFO")
        await self.ready(self.server_port, self.server)
        self.clients = {}
        for scheme, reverse in zip(("wss", "https", "wts"), self.reverse_ports):
            endpoint, udp_endpoint, extra = port(), port(), port()
            client = await self.client(scheme, endpoint=endpoint, udp=udp_endpoint, extra=extra, reverse=reverse)
            self.clients[scheme] = (endpoint, extra, client)
            await self.ready(reverse, client)
            for label, address in (("forward", endpoint), ("reverse", reverse)):
                reader, writer = await asyncio.open_connection("127.0.0.1", address)
                await self.probe(reader, writer)
                self.held_streams.append((scheme, label, reader, writer))
            sock = socket.socket(type=socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect(("127.0.0.1", udp_endpoint))
            await udp_exchange(sock, 8192)
            self.udp_sockets.append(sock)
        self.other_endpoint = port()
        await self.client("https", certificate="other", endpoint=self.other_endpoint)
        self.other_reader, self.other_writer = await asyncio.open_connection("127.0.0.1", self.other_endpoint)
        await self.probe(self.other_reader, self.other_writer)

    async def client(self, scheme, certificate="client", endpoint=None, udp=None, extra=None, reverse=None):
        self.serial += 1
        endpoint = endpoint or port()
        options = ["-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{self.target_port}"]
        if udp:
            options += ["-L", f"udp://127.0.0.1:{udp}:127.0.0.1:{self.udp_port}"]
        if extra:
            options += ["-L", f"tcp://127.0.0.1:{extra}:127.0.0.1:{self.extra_port}"]
        if reverse:
            options += ["-R", f"tcp://127.0.0.1:{reverse}:127.0.0.1:{self.target_port}"]
        process = await self.spawn(f"client-{scheme}-{self.serial}", "client", "--tls-verify-certificate",
            "--tls-certificate", self.certs / f"{certificate}.pem", "--tls-private-key", self.certs / f"{certificate}.key",
            "--connection-min-idle", "0", "--connection-retry-max-backoff", "1s", *options,
            f"{scheme}://127.0.0.1:{self.server_port}")
        await self.ready(endpoint, process)
        return process

    async def probe(self, reader, writer, size=1024):
        payload = os.urandom(size)
        writer.write(payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(size), 5) == payload

    async def live(self):
        assert self.server.returncode is None
        for _, _, reader, writer in self.held_streams:
            await self.probe(reader, writer)
        await self.probe(self.other_reader, self.other_writer)

    async def invoke(self, valid=True):
        process = await asyncio.create_subprocess_exec(str(self.binary), "reload", "--socket", str(self.control),
            env={**os.environ, "NO_COLOR": "true"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
        assert (process.returncode == 0) == valid, (stdout.decode(), stderr.decode())
        assert self.server.returncode is None
        if valid:
            match = re.search(rb"generation (\d+)", stdout)
            assert match, stdout
            return int(match[1])
        assert b"configuration reload applied" not in stdout
        return stderr.decode()

    async def reload(self, valid=True):
        result = await self.invoke(valid)
        if valid:
            self.generation += 1
            assert result == self.generation, (result, self.generation)
        return result

    async def denied(self, endpoint, allow_timeout=False):
        before = self.accepted
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            writer.write(b"denied")
            await writer.drain()
            try:
                assert await asyncio.wait_for(reader.read(1), 5) == b""
            except (ConnectionError, ssl.SSLError):
                pass
            except asyncio.TimeoutError:
                if not allow_timeout:
                    raise
            assert self.accepted == before, "denied request reached an upstream target"
        finally:
            await close(writer)

    async def case(self, name, work):
        await asyncio.wait_for(work(), 90)
        self.record(f"reload/{name}")

    async def noop(self):
        await self.reload()
        await self.live()
        for sock in self.udp_sockets:
            await udp_exchange(sock, 8192)

    async def invalid_transaction(self):
        self.limits["max_tunnels"] = 1
        self.policies()
        self.replace(self.tenant_file, '{"version":1,"broken":true}')
        await self.reload(False)
        await self.live()
        await self.exchange(self.clients["https"][0])
        self.limits["max_tunnels"] = 64
        self.policies()
        self.replace(self.certs / "server.key", (self.certs / "client.key").read_bytes())
        await self.reload(False)
        await self.live()
        self.replace(self.certs / "server.key", self.old_key)
        self.replace(self.policy, "restrictions: [")
        await self.reload(False)
        await self.exchange(self.clients["https"][0])
        self.policies()
        await self.reload()

    async def lower_quota(self):
        self.limits["max_tunnels"] = 1
        self.policies()
        await self.reload()
        await self.live()
        before = self.accepted
        await self.denied(self.clients["https"][0])
        assert self.accepted == before, "a reload reset active tunnel accounting"
        self.limits["max_tunnels"] = 64
        self.policies()
        await self.reload()
        await self.exchange(self.clients["https"][0])

    async def consistent_scope(self):
        await self.denied(self.clients["https"][1])
        self.tenants["tenants"]["alpha"]["restrictions"].append("extra")
        self.policies()
        await self.reload(False)
        self.extra_grant = True
        self.policies()
        await self.reload()
        await self.exchange(self.clients["https"][1])
        await self.live()

    async def concurrent(self):
        generations = await asyncio.gather(*(self.invoke() for _ in range(8)))
        assert sorted(generations) == list(range(self.generation + 1, self.generation + 9))
        self.generation += 8
        await self.live()

    async def sighup(self):
        os.kill(self.server.pid, signal.SIGHUP)
        expected = self.generation + 1
        for _ in range(100):
            if re.search(rf"generation={expected}\b", (self.out / "server.log").read_text()):
                self.generation = expected
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("SIGHUP did not produce a successful reload")
        await self.reload()
        await self.live()

    async def tenant_reduction(self):
        self.tenants["devices"]["runtime-device"]["roles"] = ["forwarder"]
        self.policies()
        await self.reload()
        for _, _, reader, writer in self.held_streams:
            try:
                assert await asyncio.wait_for(reader.read(1), 5) == b""
            except ConnectionError:
                pass
            await close(writer)
        self.held_streams.clear()
        await self.probe(self.other_reader, self.other_writer)
        for endpoint in self.reverse_ports:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                except OSError:
                    break
                await close(writer)
                await asyncio.sleep(0.05)
            else:
                raise AssertionError("revoked tenant reverse listener retained its socket")
        await self.exchange(self.clients["https"][0])

    async def tls_rotation(self):
        self.replace(self.certs / "server.pem", (self.certs / "renewed-server.pem").read_bytes())
        self.replace(self.certs / "server.key", (self.certs / "renewed-server.key").read_bytes())
        await self.reload()
        await self.probe(self.other_reader, self.other_writer)
        # New-only server trust proves both the TCP and QUIC acceptors switched issuer.
        self.replace(self.certs / "ca.pem", (self.certs / "replacement-ca.pem").read_bytes())
        for scheme in ("wss", "https", "wts"):
            endpoint = port()
            await self.client(scheme, endpoint=endpoint)
            await self.exchange(endpoint)
        self.replace(self.certs / "server.pem", self.old_cert)
        self.replace(self.certs / "server.key", self.old_key)
        await self.reload()
        self.replace(self.certs / "ca.pem", self.old_ca)
        for scheme in ("wss", "https", "wts"):
            endpoint = port()
            await self.client(scheme, endpoint=endpoint)
            await self.exchange(endpoint)
        await self.probe(self.other_reader, self.other_writer)

    async def client_trust(self):
        self.replace(self.client_ca, (self.certs / "replacement-ca.pem").read_bytes())
        await self.reload()
        await self.probe(self.other_reader, self.other_writer)
        for scheme in ("wss", "https", "wts"):
            endpoint = port()
            await self.client(scheme, endpoint=endpoint)
            await self.denied(endpoint, allow_timeout=True)
            endpoint = port()
            await self.client(scheme, certificate="renewed-client", endpoint=endpoint)
            await self.exchange(endpoint)
        self.replace(self.client_ca, self.old_ca)
        await self.reload()

    async def systemd_user(self):
        with tempfile.TemporaryDirectory(prefix="tw-unit-", dir="/tmp") as directory:
            directory = Path(directory)
            binary = directory / "tunward"
            shutil.copy2(self.binary, binary)
            policy, control = directory / "restrictions.yaml", directory / "reload.sock"
            self.replace(policy, f"restrictions:\n - name: unit\n   match: [Any]\n   allow:\n    - !Tunnel\n      protocol: [Tcp]\n      port: ['{self.target_port}']\n      cidr: [127.0.0.1/32]\n")
            good_policy = policy.read_bytes()
            endpoint = port()
            unit = "tunward-reload-check-" + directory.name
            reload_command = f"/usr/bin/env -i NO_COLOR=true PATH=/usr/bin:/bin {binary} reload --socket {control}"
            await self.command("systemd-run", "--user", "--collect", f"--unit={unit}", "--property=Type=exec",
                "--property=Restart=on-failure", f"--property=ExecReload={reload_command}",
                "/usr/bin/env", "-i", "NO_COLOR=true", "PATH=/usr/bin:/bin", binary,
                "server", "--reload-socket", control, "--restrict-config", policy, f"ws://127.0.0.1:{endpoint}")
            writer = None
            try:
                for _ in range(100):
                    if control.exists():
                        try:
                            _, probe = await asyncio.open_connection("127.0.0.1", endpoint)
                        except OSError:
                            pass
                        else:
                            await close(probe)
                            break
                    await asyncio.sleep(0.05)
                else:
                    raise AssertionError("user service did not start")
                async def state(property):
                    return (await self.command("systemctl", "--user", "show", unit,
                                               f"--property={property}", "--value")).decode().strip()
                pid = await state("MainPID")
                assert pid.isdigit() and int(pid) > 0
                local = port()
                client = await self.spawn("systemd-client", "client", "--connection-min-idle", "0",
                    "-L", f"tcp://127.0.0.1:{local}:127.0.0.1:{self.target_port}", f"ws://127.0.0.1:{endpoint}")
                await self.ready(local, client)
                reader, writer = await asyncio.open_connection("127.0.0.1", local)
                await self.probe(reader, writer)
                await self.command("systemctl", "--user", "reload", unit)
                assert await state("MainPID") == pid and await state("ActiveState") == "active"
                await self.probe(reader, writer)
                self.record("reload/systemd-success-keeps-pid-and-stream")
                self.replace(policy, "restrictions: [")
                process = await asyncio.create_subprocess_exec("systemctl", "--user", "reload", unit,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                await asyncio.wait_for(process.communicate(), 40)
                assert process.returncode != 0, "systemd hid the configuration rejection"
                assert await state("MainPID") == pid and await state("ActiveState") == "active"
                await self.probe(reader, writer)
                self.record("reload/systemd-rejection-keeps-service-active")
                self.replace(policy, good_policy)
                await self.command("systemctl", "--user", "reload", unit)
                assert await state("MainPID") == pid
                await self.probe(reader, writer)
                self.record("reload/systemd-recovery-keeps-pid-and-stream")
            finally:
                if writer:
                    await close(writer)
                await self.command("systemctl", "--user", "stop", unit)

    async def independent_revocation(self):
        endpoint = port()
        await self.client("https", endpoint=endpoint)
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            await self.probe(reader, writer)
            self.replace(self.revocation_file, '{"version":1,"blocked_devices":["runtime-device"]}')
            self.replace(self.quota_file, '{"version":1,"default":{"max_tunnels":0}}')
            await self.reload(False)
            try:
                assert await asyncio.wait_for(reader.read(1), 5) == b""
            except ConnectionError:
                pass
            await self.probe(self.other_reader, self.other_writer)
            self.policies()
            await self.reload()
            await self.denied(endpoint, allow_timeout=True)
            self.replace(self.revocation_file, '{"version":1,"blocked_devices":[]}')
            await asyncio.sleep(1.2)
            await self.exchange(endpoint)
        finally:
            await close(writer)
    async def run(self):
        if os.name != "posix":
            self.record("reload/unix-control", "not_run", reason="Unix reload socket and SIGHUP require a Unix server")
            self.metadata()
            return False
        with tempfile.TemporaryDirectory(prefix="tw-reload-", dir="/tmp") as control_dir:
            self.control = Path(control_dir) / "control.sock"
            current_case = "setup"
            try:
                await self.setup()
                if self.args.systemd_user:
                    current_case = "systemd-user"
                    await self.systemd_user()
                for name, work in (("preserve-tcp-reverse-and-udp", self.noop),
                    ("invalid-candidate-retains-generation", self.invalid_transaction),
                    ("quota-accounting-survives-lower-and-raise", self.lower_quota),
                    ("restriction-and-tenant-snapshot", self.consistent_scope),
                    ("serialized-concurrent-requests", self.concurrent), ("sighup", self.sighup),
                    ("tenant-grant-loss-and-reverse-cleanup", self.tenant_reduction),
                    ("server-issuer-rotation-and-rollback", self.tls_rotation),
                    ("client-ca-on-new-handshakes", self.client_trust),
                    ("revocation-survives-rejected-group", self.independent_revocation)):
                    current_case = name
                    await self.case(name, work)
            except Exception as exc:
                (self.out / "failure.log").write_text(traceback.format_exc())
                self.record(f"reload/{current_case}", "fail", error=f"{type(exc).__name__}: {exc}")
            finally:
                for _, _, _, writer in getattr(self, "held_streams", []):
                    await close(writer)
                if hasattr(self, "other_writer"):
                    await close(self.other_writer)
                for sock in getattr(self, "udp_sockets", []):
                    sock.close()
                for process in self.processes:
                    if process.returncode is None:
                        process.terminate()
                        try:
                            await asyncio.wait_for(process.wait(), 3)
                        except asyncio.TimeoutError:
                            process.kill()
                            await process.wait()
                for target in getattr(self, "targets", []):
                    target.close()
                    await target.wait_closed()
                if hasattr(self, "udp"):
                    self.udp.close()
                self.metadata()
        return any(row["status"] == "fail" for row in self.results)

    def metadata(self):
        (self.out / "metadata.json").write_text(json.dumps({"binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "openssl_version": self.openssl_version, "scope": "Unix bounded loopback reload with synthetic mTLS; no production or endurance qualification",
            "final_generation": getattr(self, "generation", None)}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward.exe" if os.name == "nt" else "target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--systemd-user", action="store_true", help="Also test an isolated transient user service; requires a running user manager")
    raise SystemExit(bool(asyncio.run(ReloadChecks(parser.parse_args()).run())))
