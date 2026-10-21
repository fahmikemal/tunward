#!/usr/bin/env python3
"""Native Python/OpenSSL smoke checks without Linux /proc, Unix sockets, Docker, or root."""
import argparse
import asyncio
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import time


def port():
    with socket.socket() as stream, socket.socket(type=socket.SOCK_DGRAM) as datagram:
        stream.bind(("127.0.0.1", 0))
        endpoint = stream.getsockname()[1]
        datagram.bind(("127.0.0.1", endpoint))
        return endpoint


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, asyncio.TimeoutError):
        pass


async def udp_exchange(sock, payload_bytes=40000):
    loop = asyncio.get_running_loop()
    data = os.urandom(payload_bytes)
    try:
        await loop.sock_sendall(sock, data)
    except OSError as exc:
        if exc.errno != errno.EMSGSIZE or payload_bytes <= 8192:
            raise
        data = os.urandom(8192)
        await loop.sock_sendall(sock, data)
    assert await asyncio.wait_for(loop.sock_recv(sock, 65536), 5) == data
    return len(data)


class RuntimeChecks:
    def __init__(self, args):
        self.args = args
        self.out = args.output.resolve()
        self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.binary = self.out / ("tunward-under-test.exe" if os.name == "nt" else "tunward-under-test")
        shutil.copy2(args.binary, self.binary)
        self.results, self.processes, self.process_logs = [], [], {}
        self.openssl_version = None

    def record(self, name, status="pass", **details):
        self.results.append({"name": name, "status": status, **details})
        (self.out / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")

    async def command(self, *args):
        process = await asyncio.create_subprocess_exec(*map(str, args), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 0, stderr.decode(errors="replace")
        return stdout

    async def prepare(self):
        self.openssl_version = (await self.command("openssl", "version")).decode().strip()
        self.certs = self.out / "certificates"
        self.certs.mkdir(mode=0o700)
        config = self.certs / "openssl.cnf"
        # OpenSSL 1.1.1 appends -addext to configured extensions, allowing duplicate CA constraints.
        config.write_text("[req]\nprompt=no\ndistinguished_name=dn\n[dn]\n"
                          "[ca]\nbasicConstraints=critical,CA:TRUE\n"
                          "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        await self.command("openssl", "req", "-config", config, "-extensions", "ca", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "4", "-subj", "/CN=Runtime Test CA",
            "-keyout", self.certs / "ca.key", "-out", self.certs / "ca.pem")
        (self.certs / "ca.key").chmod(0o600)
        for name, cn, purpose in (("server", "localhost", "serverAuth"), ("client", "runtime-device", "clientAuth")):
            await self.command("openssl", "req", "-config", config, "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-subj", f"/CN={cn}", "-keyout", self.certs / f"{name}.key", "-out", self.certs / f"{name}.csr")
            ext = self.certs / f"{name}.ext"
            ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={purpose}\n"
                           "subjectAltName=DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
            await self.command("openssl", "x509", "-req", "-in", self.certs / f"{name}.csr", "-CA", self.certs / "ca.pem",
                "-CAkey", self.certs / "ca.key", "-set_serial", "101" if name == "server" else "102", "-days", "4",
                "-extfile", ext, "-out", self.certs / f"{name}.pem")
            (self.certs / f"{name}.key").chmod(0o600)
            await self.command("openssl", "verify", "-x509_strict", "-CAfile", self.certs / "ca.pem",
                "-purpose", "sslserver" if name == "server" else "sslclient", self.certs / f"{name}.pem")

    async def spawn(self, label, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TUNWARD_") and k not in
               ("NO_COLOR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "RUST_LOG")}
        env.update(NO_COLOR="true", SSL_CERT_FILE=str(self.certs / "ca.pem"), SSL_CERT_DIR="")
        with (self.out / f"{label}.log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(str(self.binary), *map(str, args),
                "--nb-worker-threads", "1", "--log-lvl", "WARN", stdout=log, stderr=log, env=env)
        self.processes.append(process)
        self.process_logs[process.pid] = f"{label}.log"
        return process

    async def ready(self, endpoint, process):
        for _ in range(100):
            assert process.returncode is None, f"fixture exited ({process.returncode}); inspect {self.process_logs[process.pid]}"
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", endpoint)
                await close(writer)
                return
            except OSError:
                await asyncio.sleep(0.05)
        raise TimeoutError("listener did not start")

    async def exchange(self, endpoint):
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        try:
            payload = os.urandom(32768)
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload
        finally:
            await close(writer)

    async def run(self):
        try:
            await self.prepare()
        except Exception as exc:
            self.record("runtime/setup", "fail", error=f"{type(exc).__name__}: {exc}")
            self.metadata()
            return True
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                await close(writer)
        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, peer):
                self.transport.sendto(data, peer)
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
        udp_port = udp.get_extra_info("sockname")[1]
        try:
            server_port = port()
            policy = self.out / "restrictions.yaml"
            policy.write_text(f"restrictions:\n - name: Runtime target\n   match: [Any]\n   allow:\n    - !Tunnel\n      protocol: [Tcp, Udp]\n      port: ['{target_port}', '{udp_port}']\n      cidr: [127.0.0.1/32]\n    - !ReverseTunnel\n      protocol: [Tcp]\n      cidr: [127.0.0.1/32]\n")
            server = await self.spawn("server", "server", "--tls-certificate", self.certs / "server.pem",
                "--tls-private-key", self.certs / "server.key", "--tls-client-ca-certs", self.certs / "ca.pem",
                "--restrict-config", policy, f"wts://127.0.0.1:{server_port}")
            await self.ready(server_port, server)
            for scheme in ("wss", "https", "wts"):
                local, local_udp, reverse = port(), port(), port()
                client = await self.spawn(scheme, "client", "--tls-verify-certificate",
                    "--tls-certificate", self.certs / "client.pem", "--tls-private-key", self.certs / "client.key",
                    "-L", f"tcp://127.0.0.1:{local}:127.0.0.1:{target_port}",
                    "-L", f"udp://127.0.0.1:{local_udp}:127.0.0.1:{udp_port}",
                    "-R", f"tcp://127.0.0.1:{reverse}:127.0.0.1:{target_port}", f"{scheme}://127.0.0.1:{server_port}")
                await self.ready(local, client)
                for label, endpoint in (("forward-tcp", local), ("reverse-tcp", reverse)):
                    await self.ready(endpoint, client)
                    await self.exchange(endpoint)
                    self.record(f"runtime/{scheme}/{label}", payload_bytes=32768, verified_mtls=True)
                with socket.socket(type=socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    sock.connect(("127.0.0.1", local_udp))
                    size = await udp_exchange(sock)
                    if size != 40000:
                        self.record(f"runtime/{scheme}/large-udp", "not_run", requested_datagram_bytes=40000,
                                    reason="host UDP send rejected the datagram with EMSGSIZE; testing 8192 bytes")
                    self.record(f"runtime/{scheme}/udp", datagram_bytes=size, verified_mtls=True)
            context = ssl.create_default_context(cafile=self.certs / "ca.pem")
            context.load_cert_chain(self.certs / "client.pem", self.certs / "client.key")
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", server_port, ssl=context, server_hostname="wrong.invalid")
            except ssl.SSLCertVerificationError:
                self.record("runtime/wrong-server-name-denied")
            else:
                await close(writer)
                raise AssertionError("wrong certificate name accepted")
        except Exception as exc:
            self.record("runtime/suite", "fail", error=f"{type(exc).__name__}: {exc}")
        finally:
            for process in self.processes:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 3)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
            target.close()
            await target.wait_closed()
            udp.close()
            self.metadata()
        return any(r["status"] == "fail" for r in self.results)

    def metadata(self):
        (self.out / "metadata.json").write_text(json.dumps({"platform": platform.platform(),
                "openssl_version": self.openssl_version,
                "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "native TCP/reverse TCP/UDP with mTLS; no privileged routing or platform-wide feature qualification"
            }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward.exe" if os.name == "nt" else "target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(bool(asyncio.run(RuntimeChecks(parser.parse_args()).run())))
