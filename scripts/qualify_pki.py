#!/usr/bin/env python3
"""Synthetic server key/issuer renewal, old-trust denial and rollback with established mTLS tunnels."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.request

from check_tls_bundle import validate
from qualify import close, port
from qualify_quotas import QuotaChecks
from qualify_wan import certificates, command


def http_json(management, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{management}{path}", timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def http_text(management, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{management}{path}", timeout=5) as response:
        return response.status, response.read().decode()


async def handshake(endpoint, certificate, key, issuer):
    """'accepted' if the server takes the client certificate, else the TLS alert or error it got."""
    context = ssl.create_default_context(cafile=str(issuer))
    context.load_cert_chain(str(certificate), str(key))
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", endpoint, ssl=context, server_hostname="localhost"), 5)
    except (ssl.SSLError, ConnectionError) as error:
        return getattr(error, "reason", None) or type(error).__name__
    try:
        # TLS 1.3 reports a refused client certificate only after the handshake, on the first read.
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(64), 5)
        return "accepted" if response.startswith(b"HTTP/") else "closed"
    except (ssl.SSLError, ConnectionError) as error:
        return getattr(error, "reason", None) or type(error).__name__
    finally:
        await close(writer)


def publish(path, data):
    """Replace `path` atomically, as a CRL distribution job would."""
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_bytes(data)
    temporary.replace(path)


def utc(seconds_from_now):
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + seconds_from_now))


def revoked(outcome):
    return "REVOKED" in outcome.upper()


class PKIChecks(QuotaChecks):
    async def crl(self, name, revoked_certificates=(), expired=False, issuer=None):
        """A PEM CRL from the device CA, or from `issuer`'s folder, revoking the named certificates.

        It is current for a day, or past its next update by an hour when `expired`.
        """
        issuer = issuer or self.certs
        folder = self.suite.out / "crl-issuer" / name
        folder.mkdir(parents=True)
        (folder / "index.txt").write_text("")
        (folder / "crlnumber").write_text("1000\n")
        config = folder / "openssl.cnf"
        config.write_text(f"[ca]\ndefault_ca = device\n[device]\ndatabase = {folder / 'index.txt'}\n"
                          f"crlnumber = {folder / 'crlnumber'}\ndefault_md = sha256\ndefault_crl_days = 1\n")
        signer = ("-config", config, "-keyfile", issuer / "ca.key", "-cert", issuer / "ca.pem")
        for certificate in revoked_certificates:
            await command("openssl", "ca", *signer, "-revoke", self.certs / f"{certificate}.pem")
        window = ("-crl_lastupdate", utc(-7200), "-crl_nextupdate", utc(-3600)) if expired else ()
        await command("openssl", "ca", *signer, "-gencrl", *window, "-out", folder / "crl.pem")
        return (folder / "crl.pem").read_bytes()

    def crl_server_args(self, endpoint, crl, *extra):
        return ("server", f"wts://127.0.0.1:{endpoint}", "--tls-certificate", str(self.certs / "server.pem"),
                "--tls-private-key", str(self.certs / "server.key"), "--tls-client-ca-certs", str(self.certs / "ca.pem"),
                "--restrict-config", str(self.policy), "--tls-client-crl", str(crl), *extra)

    async def tunnel(self, label, transport, endpoint, identity):
        """An established connection through a client tunnel authenticated as `identity`."""
        local = port()
        client = await self.suite.spawn(label, "client", "-L", f"tcp://127.0.0.1:{local}:127.0.0.1:{self.target_port}",
            "--tls-verify-certificate", "--tls-certificate", str(self.certs / f"{identity}.pem"),
            "--tls-private-key", str(self.certs / f"{identity}.key"), "--connection-retry-max-backoff", "1s",
            f"{transport}://127.0.0.1:{endpoint}",
            extra_env={"SSL_CERT_FILE": str(self.certs / "ca.pem"), "SSL_CERT_DIR": ""})
        await self.passive_listener(local, client)
        reader, writer = await asyncio.open_connection("127.0.0.1", local)
        return client, local, reader, writer

    @staticmethod
    async def echoes(reader, writer, payload=b"crl-check"):
        try:
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.readexactly(len(payload)), 5) == payload
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            return False

    @staticmethod
    async def closed_within(reader, seconds):
        try:
            return await asyncio.wait_for(reader.read(1), seconds) == b""
        except ConnectionError:
            return True
        except asyncio.TimeoutError:
            return False

    async def crl_file_reload(self, transport):
        """A CRL file update closes the revoked certificate's sessions and refuses it afterwards."""
        endpoint, live = port(), self.suite.out / f"crl-{transport}.pem"
        publish(live, await self.crl(f"{transport}-b", ["b"]))
        label = f"pki-crl-{transport}"
        server = await self.suite.spawn(f"{label}-server", *self.crl_server_args(endpoint, live), log_level="INFO")
        processes, writers = [server], []
        try:
            await self.suite.ready(endpoint, server)
            certs = self.certs
            assert await handshake(endpoint, certs / "a.pem", certs / "a.key", certs / "ca.pem") == "accepted"
            outcome = await handshake(endpoint, certs / "b.pem", certs / "b.key", certs / "ca.pem")
            assert revoked(outcome), outcome
            client_a, _, reader_a, writer_a = await self.tunnel(f"{label}-a", transport, endpoint, "a")
            # The same device under a new certificate, as after a key rotation.
            client_r, _, reader_r, writer_r = await self.tunnel(f"{label}-rotated", transport, endpoint, "rotated-a")
            processes += [client_a, client_r]
            writers += [writer_a, writer_r]
            assert await self.echoes(reader_a, writer_a) and await self.echoes(reader_r, writer_r)

            publish(live, await self.crl(f"{transport}-a-b", ["b", "a"]))
            assert await self.closed_within(reader_a, 5), "the revoked certificate's tunnel stayed open"
            assert await self.echoes(reader_r, writer_r), "a certificate the CRL does not list lost its tunnel"
            outcome = await handshake(endpoint, certs / "a.pem", certs / "a.key", certs / "ca.pem")
            assert revoked(outcome), outcome
            log = (self.suite.out / f"{label}-server.log").read_text()
            cancelled = [int(n) for n in re.findall(r"Applied client CRLs\W+cancelled_sessions=(\d+)", log)]
            assert cancelled and max(cancelled) >= 1, cancelled
            return {"refused_at_startup": "b", "revoked_tunnel_closed": True, "rotated_certificate_kept": True,
                    "cancelled_sessions": max(cancelled), "refusal_alert": outcome}
        finally:
            await asyncio.gather(*(close(writer) for writer in writers))
            await asyncio.gather(*(self.suite.stop(process) for process in processes))

    async def crl_socket_reload(self):
        """Under --reload-socket the CRL takes effect at the acknowledged reload, not on write."""
        endpoint, live = port(), self.suite.out / "crl-managed.pem"
        control = self.suite.out / "crl-reload.sock"
        publish(live, await self.crl("managed-none"))
        command_line = self.crl_server_args(endpoint, live)
        server = await self.suite.spawn("pki-crl-managed-server", command_line[0], "--reload-socket", str(control),
                                        *command_line[1:], log_level="INFO")
        processes, writers = [server], []
        try:
            await self.suite.ready(endpoint, server)
            client, _, reader, writer = await self.tunnel("pki-crl-managed-a", "wts", endpoint, "a")
            processes.append(client)
            writers.append(writer)
            assert await self.echoes(reader, writer)
            publish(live, await self.crl("managed-a", ["a"]))
            await asyncio.sleep(2)
            assert await self.echoes(reader, writer), "the CRL applied before the reload"
            process = await asyncio.create_subprocess_exec(str(self.suite.binary), "reload", "--socket", str(control),
                env={**os.environ, "NO_COLOR": "true"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 40)
            assert process.returncode == 0, (stdout, stderr)
            disconnected = int(re.search(rb"disconnected sessions (\d+)", stdout).group(1))
            assert disconnected >= 1, stdout
            assert await self.closed_within(reader, 5), "the revoked certificate's tunnel stayed open"
            certs = self.certs
            outcome = await handshake(endpoint, certs / "a.pem", certs / "a.key", certs / "ca.pem")
            assert revoked(outcome), outcome
            return {"applied_on_write": False, "disconnected_sessions": disconnected, "refusal_alert": outcome}
        finally:
            await asyncio.gather(*(close(writer) for writer in writers))
            await asyncio.gather(*(self.suite.stop(process) for process in processes))

    async def crl_expiry(self):
        """An expired CRL refuses clients and degrades /healthz unless expiry is allowed."""
        results = {}
        live = self.suite.out / "crl-expired.pem"
        publish(live, await self.crl("expired", expired=True))
        certs = self.certs
        for allow in (False, True):
            endpoint, management = port(), port()
            extra = ("--management-api", f"127.0.0.1:{management}") + (("--tls-client-crl-allow-expired",) if allow else ())
            label = f"pki-crl-expired-{'allowed' if allow else 'enforced'}"
            server = await self.suite.spawn(label, *self.crl_server_args(endpoint, live, *extra))
            try:
                await self.suite.ready(endpoint, server)
                outcome = await handshake(endpoint, certs / "a.pem", certs / "a.key", certs / "ca.pem")
                status, health = await asyncio.to_thread(http_json, management, "/healthz")
                _, metrics = await asyncio.to_thread(http_text, management, "/metrics")
                assert health["tls_client_crl_expired"] is True, health
                assert "tunward_tls_client_crl_next_update_seconds " in metrics
                if allow:
                    assert outcome == "accepted" and status == 200 and health["status"] == "healthy", (outcome, health)
                else:
                    assert outcome != "accepted" and status == 503 and health["status"] == "degraded", (outcome, health)
                results["allowed" if allow else "enforced"] = {"handshake": outcome, "healthz": status}
            finally:
                await self.suite.stop(server)
        return results

    async def crl_rejections(self):
        """A CRL that cannot be used stops startup, and on reload leaves the previous one in force."""
        renewed = self.suite.out / "crl-impostor-ca"
        await certificates(renewed, "127.0.0.1")
        impostor = self.suite.out / "crl-impostor.pem"
        # The same CA name, another key: as from a CA that was re-keyed.
        publish(impostor, await self.crl("impostor", issuer=renewed))
        process = await asyncio.create_subprocess_exec(str(self.suite.binary), "server", "--test-config",
            *self.crl_server_args(port(), impostor)[1:], env={**os.environ, "NO_COLOR": "true"},
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode != 0 and b"is not signed by the client CA of that name" in stdout + stderr, (stdout, stderr)

        endpoint, live = port(), self.suite.out / "crl-kept.pem"
        publish(live, await self.crl("kept-b", ["b"]))
        server = await self.suite.spawn("pki-crl-kept", *self.crl_server_args(endpoint, live))
        certs = self.certs
        try:
            await self.suite.ready(endpoint, server)
            for data in (b"not a CRL", impostor.read_bytes()):
                publish(live, data)
                await asyncio.sleep(2)
                assert await handshake(endpoint, certs / "a.pem", certs / "a.key", certs / "ca.pem") == "accepted"
                outcome = await handshake(endpoint, certs / "b.pem", certs / "b.key", certs / "ca.pem")
                assert revoked(outcome), outcome
            warnings = (self.suite.out / "pki-crl-kept.log").read_text().count("Error while loading TLS file")
            assert 2 <= warnings <= 6, warnings
            return {"startup_refused": True, "unusable_and_impostor_writes_kept_previous": True, "warnings": warnings}
        finally:
            await self.suite.stop(server)

    async def invalid_trust_write(self):
        """An invalid write to a watched TLS file is reported once, and the next write still loads."""
        endpoint, trust = port(), self.suite.out / "watched-ca.pem"
        trust.write_bytes((self.certs / "ca.pem").read_bytes())
        server = await self.suite.spawn("pki-invalid-ca-write", "server", f"wss://127.0.0.1:{endpoint}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(trust), "--restrict-config", str(self.policy))
        log = self.suite.out / "pki-invalid-ca-write.log"
        try:
            await self.suite.ready(endpoint, server)
            trust.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            await asyncio.sleep(3)
            warnings = log.read_text().count("Error while loading TLS file")
            # One per write event the invalid content produced; the old reloader logged thousands a second.
            assert 1 <= warnings <= 3, warnings
            assert await handshake(endpoint, self.certs / "a.pem", self.certs / "a.key", self.certs / "ca.pem") == "accepted"
            trust.write_bytes((self.certs / "ca.pem").read_bytes())
            await asyncio.sleep(1)
            assert log.read_text().count("Error while loading TLS file") == warnings
            assert await handshake(endpoint, self.certs / "a.pem", self.certs / "a.key", self.certs / "ca.pem") == "accepted"
            return {"warnings_for_invalid_write": warnings, "previous_trust_kept": True, "valid_rewrite_loads_without_warning": True}
        finally:
            await self.suite.stop(server)

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
            await self.suite.check("pki/invalid-client-ca-write", self.invalid_trust_write, 20)
            for transport in ("wss", "https", "wts"):
                await self.suite.check(f"pki/crl/{transport}/file-reload-closes-revoked-sessions",
                                       lambda transport=transport: self.crl_file_reload(transport), 60)
            await self.suite.check("pki/crl/socket-reload-closes-revoked-sessions", self.crl_socket_reload, 60)
            await self.suite.check("pki/crl/expired", self.crl_expiry, 40)
            await self.suite.check("pki/crl/unusable-files", self.crl_rejections, 40)
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
                "scope": "disposable loopback PKI; separate server issuer/key rotation and rollback; device CA unchanged; device CRLs from the same disposable CA; not public ACME issuance, CRL distribution points or production activation"
            }, indent=2) + "\n")
        return any(r["status"] == "fail" for r in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(PKIChecks(parser.parse_args()).run())))
