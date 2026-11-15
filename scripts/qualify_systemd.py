#!/usr/bin/env python3
"""Qualify the production system unit inside a disposable Ubuntu 24.04 container.

Requires Linux and Docker with privileged containers and private cgroup v2.
No host service, published port, host bind mount or registry publication is used.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

from qualify_runtime import RuntimeChecks, close, port, udp_exchange


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def container_guard():
    # The destructive fixture provisioning below is never a host setup command.
    assert os.geteuid() == 0 and Path("/.dockerenv").exists(), "container fixture only"
    assert Path("/proc/1/comm").read_text().strip() == "systemd", "systemd must be container PID 1"
    assert Path("/run/systemd/container").read_text().strip() == "docker", "Docker system manager required"
    assert Path("/qualification/CONTAINER_ONLY").read_text().strip() == "tunward-systemd-qualification-v1"


class SystemdChecks(RuntimeChecks):
    def __init__(self, args):
        container_guard()
        super().__init__(args)
        self.started = time.time()
        self.streams, self.datagrams, self.targets = [], [], []
        self.udp = None
        self.client_processes = {}
        self.serial = 0
        self.unit = "tunward.service"
        self.policy = Path("/etc/tunward/restrictions.yaml")
        self.unit_source = Path("/qualification/tunward.service")
        self.unit_path = Path("/etc/systemd/system/tunward.service")
        self.database = Path("/var/lib/tunward/devices.sqlite3")

    async def ctl(self, *args, success=True):
        process = await asyncio.create_subprocess_exec("systemctl", *args, self.unit,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
        assert (process.returncode == 0) == success, (args, process.returncode, stdout.decode(), stderr.decode())
        return stdout.decode()

    async def state(self):
        result = await self.ctl("show", "--all", "--no-pager")
        return dict(line.split("=", 1) for line in result.splitlines() if "=" in line)

    async def api(self, path="/healthz"):
        def fetch():
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://127.0.0.1:8081" + path, timeout=2) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                return json.load(response)
        return await asyncio.to_thread(fetch)

    async def healthy(self, previous_pid=None):
        deadline = asyncio.get_running_loop().time() + 30
        while asyncio.get_running_loop().time() < deadline:
            state = await self.state()
            if state["ActiveState"] == "active" and int(state["MainPID"]) not in (0, previous_pid):
                try:
                    assert (await self.api())["status"] == "healthy"
                    return state
                except (OSError, AssertionError, urllib.error.URLError):
                    pass
            await asyncio.sleep(0.1)
        raise AssertionError(f"service did not become healthy: {await self.state()}")

    def publish(self, path, data):
        path = Path(path)
        candidate = path.with_name(path.name + ".candidate")
        candidate.write_bytes(data.encode() if isinstance(data, str) else data)
        os.chown(candidate, 0, self.account.pw_gid)
        candidate.chmod(0o640)
        candidate.replace(path)

    def policies(self, extra=False):
        ports = [self.target_port, self.udp_port] + ([self.extra_port] if extra else [])
        return ("restrictions:\n - name: traffic\n   match: [Any]\n   allow:\n"
                "    - !Tunnel\n      protocol: [Tcp, Udp]\n"
                f"      port: {json.dumps(list(map(str, ports)))}\n      cidr: [127.0.0.1/32]\n"
                "    - !ReverseTunnel\n      protocol: [Tcp]\n      cidr: [127.0.0.1/32]\n")

    async def setup(self):
        await self.prepare()
        await self.command("useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "tunward")
        self.account = pwd.getpwnam("tunward")
        for directory in ("/etc/tunward", "/etc/tunward/tls"):
            Path(directory).mkdir(mode=0o750)
            os.chown(directory, 0, self.account.pw_gid)
        release = Path("/opt/tunward/releases") / digest(self.binary)
        release.mkdir(parents=True)
        shutil.copy2(self.binary, release / "tunward")
        (release / "tunward").chmod(0o755)
        Path("/opt/tunward/current").symlink_to(release, target_is_directory=True)
        shutil.copy2(self.unit_source, self.unit_path)
        assert digest(self.unit_source) == digest(self.unit_path)
        await self.command("systemd-analyze", "verify", self.unit_path)
        await self.command("systemctl", "daemon-reload")

        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                await close(writer)
        for _ in range(2):
            self.targets.append(await asyncio.start_server(echo, "127.0.0.1", 0))
        self.target_port, self.extra_port = [t.sockets[0].getsockname()[1] for t in self.targets]
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, peer):
                self.transport.sendto(data, peer)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp.get_extra_info("sockname")[1]
        self.reverse_ports = [port() for _ in range(3)]
        self.publish(self.policy, self.policies())
        self.publish("/etc/tunward/tenants.yaml", json.dumps({"version": 1,
            "roles": {"agent": ["forward_tcp", "forward_udp", "reverse_tcp"]},
            "tenants": {"fixture": {"restrictions": ["traffic"], "reverse_bindings": [
                {"address": "127.0.0.1", "ports": list(map(str, self.reverse_ports))}]}},
            "devices": {"runtime-device": {"tenant": "fixture", "roles": ["agent"]}}}))
        self.publish("/etc/tunward/quotas.yaml", json.dumps({"version": 1, "default": {
            "max_sessions": 32, "max_tunnels": 64, "requests_per_second": 100, "request_burst": 200,
            "upload_bytes_per_second": 4194304, "download_bytes_per_second": 4194304,
            "bandwidth_burst_bytes": 65536}}))
        self.publish("/etc/tunward/revocations.yaml", '{"version":1,"blocked_devices":[]}')
        for source, destination in (("server.pem", "server.pem"), ("server.key", "server.key"), ("ca.pem", "client-ca.pem")):
            self.publish(Path("/etc/tunward/tls") / destination, (self.certs / source).read_bytes())
        Path("/tmp/tunward-outside-marker").write_text("outside")
        self.record("systemd/unmodified-template", unit_sha256=digest(self.unit_source))

    async def startup_rejections(self):
        key = Path("/etc/tunward/tls/server.key")
        os.chown(key, 0, 0)
        key.chmod(0o600)
        await self.ctl("start", success=False)
        state = await self.state()
        assert state["MainPID"] == "0"
        await self.ctl("stop")
        self.record("systemd/unreadable-key-rejected-before-main")
        os.chown(key, 0, self.account.pw_gid)
        key.chmod(0o640)
        self.publish(self.policy, "restrictions: [invalid]")
        await self.ctl("start", success=False)
        assert (await self.state())["MainPID"] == "0"
        await self.ctl("stop")
        self.publish(self.policy, self.policies())
        self.record("systemd/invalid-policy-rejected-before-main")

    async def sandbox(self, state):
        pid = int(state["MainPID"])
        assert state["User"] == state["Group"] == "tunward"
        for key, expected in {"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                "PrivateDevices": "yes", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "",
                "AmbientCapabilities": "", "UMask": "0077"}.items():
            assert state[key] == expected, (key, state[key])
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        assert set(map(int, status["Uid"].split())) == {self.account.pw_uid}
        assert int(status["CapEff"], 16) == int(status["CapBnd"], 16) == 0
        assert int(status["NoNewPrivs"]) == 1
        assert digest(f"/proc/{pid}/exe") == digest(self.binary)
        for directory in ("/run/tunward", "/var/lib/tunward"):
            st = Path(directory).stat()
            assert st.st_uid == self.account.pw_uid and st.st_mode & 0o777 == 0o700
        control = Path("/run/tunward/reload.sock").stat()
        assert control.st_uid == self.account.pw_uid and control.st_mode & 0o777 == 0o600

        # First prove DAC permits this account to write the canary outside the
        # service namespace. EROFS inside then tests the actual ProtectSystem mount.
        canary = Path("/usr/local/share/tunward-sandbox-canary")
        canary.write_text("baseline")
        os.chown(canary, self.account.pw_uid, self.account.pw_gid)
        canary.chmod(0o600)
        await self.command("runuser", "-u", "tunward", "--", "python3", "-c",
            f"from pathlib import Path; Path('{canary}').write_text('baseline')")
        probe = '''import errno, json
from pathlib import Path
assert Path('/etc/tunward/tls/server.key').read_bytes()
try:
    Path('/etc/tunward/restrictions.yaml').open('ab')
except OSError:
    pass
else:
    raise AssertionError('service can write administrator policy')
try:
    Path('/usr/local/share/tunward-sandbox-canary').write_text('changed')
except OSError as exc:
    assert exc.errno == errno.EROFS, exc
else:
    raise AssertionError('ProtectSystem did not restrict writes')
assert not Path('/tmp/tunward-outside-marker').exists()
Path('/tmp/tunward-inside-marker').write_text('private')
for directory in ('/run/tunward', '/var/lib/tunward'):
    p = Path(directory) / 'permission-probe'
    p.write_text('allowed')
    p.unlink()
print(json.dumps({'key_readable': True, 'policy_write_denied': True, 'system_write_errno': errno.EROFS,
                  'private_tmp': True, 'runtime_and_state_writable': True}))
'''
        output = await self.command("nsenter", "--target", pid, "--mount", "--", "runuser", "-u", "tunward", "--", "python3", "-c", probe)
        assert canary.read_text() == "baseline" and not Path("/tmp/tunward-inside-marker").exists()
        (self.out / "sandbox-probe.json").write_bytes(output)
        (self.out / "service-properties.json").write_text(json.dumps(state, indent=2) + "\n")
        (self.out / "service-process-status.txt").write_text(Path(f"/proc/{pid}/status").read_text())
        self.record("systemd/service-account-and-live-sandbox", **json.loads(output))

    async def clients(self):
        items = []
        for scheme, reverse in zip(("wss", "https", "wts"), self.reverse_ports):
            self.serial += 1
            forward, datagram, extra = port(), port(), port()
            process = await self.spawn(f"client-{scheme}-{self.serial}", "client", "--tls-verify-certificate",
                "--tls-certificate", self.certs / "client.pem", "--tls-private-key", self.certs / "client.key",
                "--connection-min-idle", "0", "--connection-retry-max-backoff", "1s",
                "--websocket-ping-frequency", "1s",
                "--reverse-tunnel-connection-retry-max-backoff", "1s",
                "-L", f"tcp://127.0.0.1:{forward}:127.0.0.1:{self.target_port}",
                "-L", f"udp://127.0.0.1:{datagram}:127.0.0.1:{self.udp_port}",
                "-L", f"tcp://127.0.0.1:{extra}:127.0.0.1:{self.extra_port}",
                "-R", f"tcp://127.0.0.1:{reverse}:127.0.0.1:{self.target_port}", f"{scheme}://127.0.0.1:8443")
            await self.ready(forward, process)
            await self.ready(reverse, process)
            self.client_processes[scheme] = process
            sock = socket.socket(type=socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect(("127.0.0.1", datagram))
            self.datagrams.append(sock)
            for endpoint in (forward, reverse):
                reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                self.streams.append((reader, writer))
            items.append((scheme, forward, reverse, extra, sock))
        return items

    async def live(self):
        for reader, writer in self.streams:
            payload = os.urandom(8192)
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload

    async def traffic(self, phase, clients):
        for scheme, forward, reverse, _, sock in clients:
            # Reconnect is asynchronous after systemd restarts the server.
            # Bound readiness to the client's lifetime rather than sleeping or
            # retrying failed data assertions.
            await self.ready(reverse, self.client_processes[scheme])
            await self.exchange(forward)
            await self.exchange(reverse)
            size = await udp_exchange(sock)
            assert size == 40000
            self.record(f"systemd/{phase}/{scheme}/forward-reverse-udp", verified_mtls=True, datagram_bytes=size)

    async def reloads(self, clients, pid):
        for _, _, _, extra, _ in clients:
            reader, writer = await asyncio.open_connection("127.0.0.1", extra)
            try:
                assert await asyncio.wait_for(reader.read(1), 5) == b"", "ungranted destination was reached"
            finally:
                await close(writer)
        self.publish(self.policy, self.policies(extra=True))
        await self.ctl("reload")
        assert (await self.state())["MainPID"] == pid
        await self.live()
        for _, _, _, extra, _ in clients:
            await self.exchange(extra)
        self.record("systemd/reload-applies-policy-keeps-pid-and-streams")
        self.publish(self.policy, "restrictions: [invalid]")
        await self.ctl("reload", success=False)
        state = await self.state()
        assert state["ActiveState"] == "active" and state["MainPID"] == pid
        await self.live()
        for _, _, _, extra, _ in clients:
            await self.exchange(extra)
        self.record("systemd/rejected-reload-retains-previous-policy-and-streams")
        self.publish(self.policy, self.policies(extra=True))
        await self.ctl("reload")
        assert (await self.state())["MainPID"] == pid
        await self.live()
        self.record("systemd/reload-recovers-without-restart")

    async def inventory(self):
        return {row["id"]: row for row in (await self.api("/api/v1/devices"))["devices"]}

    async def run(self):
        try:
            await self.setup()
            await self.startup_rejections()
            await self.ctl("start")
            await self.ctl("reset-failed")
            state = await self.healthy()
            await self.sandbox(state)
            clients = await self.clients()
            await self.traffic("start", clients)
            await self.live()
            await self.reloads(clients, state["MainPID"])
            await self.traffic("after-reload", clients)
            inventory = await self.inventory()
            assert "runtime-device" in inventory
            await self.ctl("kill", "--signal=KILL")
            restarted = await self.healthy(previous_pid=int(state["MainPID"]))
            assert int(restarted["NRestarts"]) >= 1
            assert restarted["InvocationID"] != state["InvocationID"]
            await self.traffic("after-crash-restart", clients)
            await self.ctl("reload")
            assert (await self.state())["MainPID"] == restarted["MainPID"]
            after = await self.inventory()
            assert set(after) == set(inventory)
            assert after["runtime-device"]["first_seen_at"] == inventory["runtime-device"]["first_seen_at"]
            assert after["runtime-device"]["observed_connections"] > inventory["runtime-device"]["observed_connections"]
            self.record("systemd/crash-restart-cleans-runtime-socket-preserves-inventory")
            await self.ctl("stop")
            assert (await self.state())["MainPID"] == "0" and not Path("/run/tunward").exists()
            with sqlite3.connect(self.database) as database:
                assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
                with sqlite3.connect(self.out / "inventory-backup.sqlite3") as backup:
                    database.backup(backup)
            self.record("systemd/stop-cleans-runtime-keeps-consistent-state")
        except Exception as exc:
            self.record("systemd/suite", "fail", error=f"{type(exc).__name__}: {exc}")
        finally:
            for process in self.processes:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 3)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
            for _, writer in self.streams:
                await close(writer)
            for sock in self.datagrams:
                sock.close()
            for target in self.targets:
                target.close()
                await target.wait_closed()
            if self.udp:
                self.udp.close()
            try:
                await self.ctl("stop")
                await self.command("journalctl", "--sync")
                (self.out / "service-journal.txt").write_bytes(await self.command("journalctl", "-b", "-u", self.unit, "--no-pager"))
            except Exception as exc:
                self.record("systemd/cleanup", "fail", error=f"{type(exc).__name__}: {exc}")
            await self.metadata_receipt()
        return any(row["status"] != "pass" for row in self.results)

    async def metadata_receipt(self):
        failed = any(row["status"] != "pass" for row in self.results)
        receipt = {"status": "failed" if failed else "completed", "exit_code": int(failed),
            "elapsed_seconds": round(time.time() - self.started, 3), "binary_sha256": digest(self.binary),
            "runner_sha256": digest(__file__), "helper_sha256": digest(Path(__file__).with_name("qualify_runtime.py")),
            "unit_sha256": digest(self.unit_source), "installed_unit_sha256": digest(self.unit_path) if self.unit_path.exists() else None,
            "results_sha256": digest(self.out / "results.json"),
            "client_heartbeat_seconds": 1, "reverse_listener_readiness_seconds": 5,
            "systemd_version": (await self.command("systemd", "--version")).decode().splitlines()[0],
            "os_release": Path("/etc/os-release").read_text(),
            "scope": "Ubuntu 24.04 system unit in a disposable privileged Docker container; synthetic mTLS and loopback; not host integration, real issuers, WAN or capacity"}
        (self.out / "completion.json").write_text(json.dumps(receipt, indent=2) + "\n")


def host(args):
    assert sys.platform == "linux", "Linux Docker host required"
    assert args.binary.is_file(), args.binary
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    name = "tunward-systemd-" + uuid.uuid4().hex
    image = name + ":local"
    container = None
    started = time.time()
    status = 1

    def interrupted(signum, frame):
        raise InterruptedError(f"interrupted by signal {signum}")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)

    try:
        with tempfile.TemporaryDirectory(prefix="tw-systemd-") as directory:
            context = Path(directory)
            shutil.copy2(args.binary, context / "tunward")
            for source, destination in ((root / "Dockerfile.systemd-qualification", "Dockerfile"),
                    (root / "deploy/tunward.service", "tunward.service"),
                    (Path(__file__), "qualify_systemd.py"), (root / "scripts/qualify_runtime.py", "qualify_runtime.py")):
                shutil.copy2(source, context / destination)
            env = os.environ.copy()
            env.setdefault("BUILDX_CONFIG", str(context / "buildx"))
            with (out / "build.log").open("wb") as log:
                subprocess.run(["docker", "build", "--tag", image, str(context)], env=env,
                    stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
            (out / "image.json").write_bytes(subprocess.check_output(["docker", "image", "inspect", image]))
            container = subprocess.check_output(["docker", "run", "--detach", "--name", name,
                "--privileged", "--cgroupns", "private", "--network", "none", "--cpus", "2", "--memory", "768m",
                "--pids-limit", "512", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", image], text=True).strip()
            inspection = json.loads(subprocess.check_output(["docker", "inspect", container], timeout=20))[0]
            assert not inspection["HostConfig"]["Binds"]
            assert inspection["HostConfig"]["NetworkMode"] == "none"
            assert inspection["HostConfig"]["CgroupnsMode"] == "private"
            (out / "container.json").write_text(json.dumps(inspection, indent=2) + "\n")
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                result = subprocess.run(["docker", "exec", container, "systemctl", "is-system-running"], capture_output=True, timeout=5)
                if result.stdout.strip() in (b"running", b"degraded"):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("container systemd did not become ready")
            with (out / "runner.log").open("wb") as log:
                result = subprocess.run(["docker", "exec", container, "python3", "/qualification/qualify_systemd.py",
                    "--inside-container", "--binary", "/qualification/tunward", "--output", "/evidence/run"],
                    stdout=log, stderr=subprocess.STDOUT, timeout=180)
            status = result.returncode
    except Exception as exc:
        (out / "host-error.txt").write_text(f"{type(exc).__name__}: {exc}\n")
    finally:
        exists = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=20).returncode == 0
        if exists:
            subprocess.run(["docker", "cp", name + ":/evidence", str(out / "evidence")], capture_output=True, timeout=30)
            logs = subprocess.run(["docker", "logs", name], capture_output=True, timeout=20)
            (out / "container.log").write_bytes(logs.stdout + logs.stderr)
            subprocess.run(["docker", "rm", "--force", name], check=True, stdout=subprocess.DEVNULL, timeout=30)
        subprocess.run(["docker", "image", "rm", image], capture_output=True, timeout=30)
        receipt = out / "evidence/run/completion.json"
        try:
            if status == 0:
                assert receipt.exists(), "missing container completion receipt"
                value = json.loads(receipt.read_text())
                assert value["status"] == "completed" and value["exit_code"] == 0
                assert value["binary_sha256"] == digest(args.binary)
                assert value["runner_sha256"] == digest(__file__)
                assert value["helper_sha256"] == digest(root / "scripts/qualify_runtime.py")
                assert value["installed_unit_sha256"] == value["unit_sha256"] == digest(root / "deploy/tunward.service")
                assert value["results_sha256"] == digest(receipt.with_name("results.json"))
        except Exception as exc:
            status = 1
            (out / "receipt-error.txt").write_text(f"{type(exc).__name__}: {exc}\n")
        (out / "completion.json").write_text(json.dumps({"status": "completed" if status == 0 else "failed",
            "exit_code": status, "elapsed_seconds": round(time.time() - started, 3),
            "container_removed": True, "binary_sha256": digest(args.binary),
            "runner_sha256": digest(__file__), "unit_sha256": digest(root / "deploy/tunward.service"),
            "dockerfile_sha256": digest(root / "Dockerfile.systemd-qualification"),
            "inner_receipt_sha256": digest(receipt) if receipt.exists() else None,
            "scope": "disposable Ubuntu systemd fixture; no host service or host bind mounts"}, indent=2) + "\n")
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inside-container", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.inside_container:
        raise SystemExit(int(asyncio.run(SystemdChecks(arguments).run())))
    raise SystemExit(host(arguments))
