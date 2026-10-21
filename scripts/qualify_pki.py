#!/usr/bin/env python3
"""Synthetic server key/issuer renewal, old-trust denial and rollback with established mTLS tunnels."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from check_tls_bundle import validate
from qualify import close, port
from qualify_quotas import QuotaChecks
from qualify_wan import certificates, command


class PKIChecks(QuotaChecks):
    async def run(self):
        await self.prepare()
        renewed = self.suite.out / "renewed"
        await certificates(renewed, "127.0.0.1")
        no_san = renewed / "no-san.ext"
        no_san.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
        await command("openssl", "x509", "-req", "-in", renewed / "server.csr", "-CA", renewed / "ca.pem",
                      "-CAkey", renewed / "ca.key", "-set_serial", "900", "-days", "4",
                      "-extfile", no_san, "-out", renewed / "cn-only.pem")
        try:
            for name, certificate, key, ca, server_name, days, allowed in (
                ("valid", renewed / "server.pem", renewed / "server.key", renewed / "ca.pem", "127.0.0.1", 1, True),
                ("mismatched-key", renewed / "server.pem", self.certs / "server.key", renewed / "ca.pem", "127.0.0.1", 1, False),
                ("wrong-name", renewed / "server.pem", renewed / "server.key", renewed / "ca.pem", "unrelated.invalid", 1, False),
                ("short-lifetime", renewed / "server.pem", renewed / "server.key", renewed / "ca.pem", "127.0.0.1", 30, False),
                ("cn-only", renewed / "cn-only.pem", renewed / "server.key", renewed / "ca.pem", "localhost", 1, False),
            ):
                async def check(cert=certificate, private=key, issuer=ca, host=server_name, horizon=days, expected=allowed):
                    try:
                        validate(cert, private, issuer, host, horizon)
                        accepted = True
                    except ValueError:
                        accepted = False
                    assert accepted == expected
                    return {"accepted": accepted, "expected": expected}
                await self.suite.check(f"pki/preflight/{name}", check)
            for scheme in ("wss", "https", "wts"):
                async def rotation(transport=scheme):
                    endpoint = port()
                    live_cert, live_key = [self.suite.out / f"{transport}-{suffix}" for suffix in ("server.pem", "server.key")]
                    def activate(folder):
                        for source, destination in ((folder / "server.pem", live_cert), (folder / "server.key", live_key)):
                            temporary = destination.with_suffix(".next")
                            temporary.write_bytes(source.read_bytes())
                            temporary.chmod(0o600)
                            temporary.replace(destination)
                    activate(self.certs)
                    server = await self.suite.spawn(f"pki-{transport}-server", "server", f"wts://127.0.0.1:{endpoint}",
                        "--tls-certificate", str(live_cert), "--tls-private-key", str(live_key),
                        "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(self.policy))
                    clients, connections = [], []
                    async def connect(label, issuer):
                        local = port()
                        client = await self.suite.spawn(f"pki-{transport}-{label}", "client",
                            "-L", f"tcp://127.0.0.1:{local}:127.0.0.1:{self.target_port}",
                            "--tls-verify-certificate", "--tls-certificate", str(self.certs / "a.pem"),
                            "--tls-private-key", str(self.certs / "a.key"), "--connection-retry-max-backoff", "1s",
                            f"{transport}://127.0.0.1:{endpoint}",
                            extra_env={"SSL_CERT_FILE": str(issuer), "SSL_CERT_DIR": ""})
                        clients.append(client)
                        await self.passive_listener(local, client)
                        reader, writer = await asyncio.open_connection("127.0.0.1", local)
                        connections.append((reader, writer))
                        return reader, writer
                    async def ping(connection):
                        reader, writer = connection
                        payload = b"renewal-and-rollback"
                        writer.write(payload)
                        await writer.drain()
                        assert await asyncio.wait_for(reader.readexactly(len(payload)), 3) == payload
                    try:
                        await self.suite.ready(endpoint, server)
                        old = await connect("original", self.certs / "ca.pem")
                        await ping(old)
                        activate(renewed)
                        await asyncio.sleep(7)
                        new = await connect("renewed-key-and-issuer", renewed / "ca.pem")
                        await ping(new)
                        await ping(old)
                        self.suite.record(f"pki/{transport}/key-and-issuer-renewal", established_session_preserved=True,
                                          fresh_connection_verifies_new_issuer=True)
                        before = self.accepted
                        rejected = await connect("old-trust-rejected", self.certs / "ca.pem")
                        try:
                            await ping(rejected)
                        except (ConnectionError, asyncio.IncompleteReadError):
                            pass
                        else:
                            raise AssertionError("old-only trust accepted new issuer")
                        assert self.accepted == before
                        self.suite.record(f"pki/{transport}/old-trust-denied", no_target_opened=True)
                        activate(self.certs)
                        await asyncio.sleep(7)
                        restored = await connect("rollback", self.certs / "ca.pem")
                        await ping(restored)
                        await ping(new)
                        await ping(old)
                        self.suite.record(f"pki/{transport}/rollback", original_issuer_and_key_restored=True,
                                          old_and_new_established_connections_preserved=True)
                    finally:
                        await asyncio.gather(*(close(writer) for _, writer in connections))
                        await asyncio.gather(*(self.suite.stop(client) for client in clients))
                        await self.suite.stop(server)
                await self.suite.check(f"pki/{scheme}/suite", rotation, 45)
        finally:
            self.target.close()
            await self.target.wait_closed()
            self.udp.close()
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "disposable loopback PKI; separate server issuer/key rotation and rollback; device CA unchanged; not public ACME issuance or production activation"
            }, indent=2) + "\n")
        return any(r["status"] == "fail" for r in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(PKIChecks(parser.parse_args()).run())))
