#!/usr/bin/env python3
"""Bounded loopback checks for transport parity and persistent verified-device inventory."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import signal
import sqlite3
import ssl
import urllib.error
import urllib.request

from qualify import close, port
from qualify_quotas import QuotaChecks
from qualify_wan import command


class FleetChecks(QuotaChecks):
    async def prepare(self):
        await super().prepare()
        self.policy.write_text(self.policy.read_text().replace("device-[ab]", "device-[abc]"))
        await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", "/CN=device-c", "-keyout", self.certs / "c.key", "-out", self.certs / "c.csr")
        await command("openssl", "x509", "-req", "-in", self.certs / "c.csr", "-CA", self.certs / "ca.pem",
                      "-CAkey", self.certs / "ca.key", "-set_serial", "901", "-days", "4",
                      "-extfile", self.certs / "client.ext", "-out", self.certs / "c.pem")
        (self.certs / "c.key").chmod(0o600)

    @asynccontextmanager
    async def server(self, label, database=None, capacity=10000, cleartext=False):
        self.serial += 1
        prefix = f"{self.serial}-{label}"
        sp, mp = port(), port()
        database = database or self.suite.out / f"{prefix}.sqlite3"
        options = [] if cleartext else [
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--fleet-inventory", str(database),
            "--fleet-inventory-max-devices", str(capacity)]
        process = await self.suite.spawn(prefix, "server", f'{"ws" if cleartext else "wts"}://127.0.0.1:{sp}',
            *options, "--management-api", f"127.0.0.1:{mp}", "--restrict-config", str(self.policy),
            "--websocket-ping-frequency", "1s", "--remote-to-local-server-idle-timeout", "3s")
        stack = {"port": sp, "management": mp, "prefix": prefix, "clients": [], "writers": [],
                 "database": database, "process": process}
        try:
            await self.suite.ready(mp, process)
            yield stack
        finally:
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await asyncio.gather(*(self.suite.stop(client) for client in stack["clients"]))
            await self.suite.stop(process)

    async def api(self, stack, path):
        return await self.suite.api(stack["management"], path)

    async def response(self, stack, path, method="GET"):
        def fetch():
            request = urllib.request.Request(f'http://127.0.0.1:{stack["management"]}{path}', method=method)
            try:
                # The URL is always the loopback management API started by this suite.
                response = urllib.request.urlopen(request, timeout=5)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, json.load(response)
        return await asyncio.to_thread(fetch)

    async def settled(self, stack):
        for _ in range(400):
            health = await self.api(stack, "/healthz")
            if health["active_clients"] == health["active_connections"] == health["active_sessions"] == 0:
                return
            await asyncio.sleep(0.03)
        raise AssertionError(f"fleet did not clear after close/cancel: {health}")

    async def parity(self):
        async with self.server("parity") as stack:
            for scheme in ("wss", "https", "wts"):
                endpoint, _ = await self.client(stack, scheme, label="same-label")
                await self.held(stack, endpoint)
            clients = await self.api(stack, "/api/v1/clients")
            assert len(clients) == 1 and clients[0]["active_tunnels"] == 3, clients
            sessions = await self.api(stack, "/api/v1/sessions")
            assert len(sessions) == 3 and all(s["kind"] == "tunnel" for s in sessions), sessions
            assert {s["transport"] for s in sessions} == {"wss", "https", "wts"}
            assert all(s["verified_device_id"] == "device-a" and s["connection_id"] for s in sessions)
            endpoint, _ = await self.client(stack, "wts", "b", "same-label")
            await self.held(stack, endpoint)
            devices = (await self.api(stack, "/api/v1/devices"))["devices"]
            assert {d["id"] for d in devices} == {"device-a", "device-b"}, devices
            assert sum(d["active_tunnels"] for d in devices) == 4
            def fetch_metrics():
                # The URL is always the loopback management API started by this suite.
                with urllib.request.urlopen(f'http://127.0.0.1:{stack["management"]}/metrics') as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    return r.read().decode()
            metrics = await asyncio.to_thread(fetch_metrics)
            assert "tunward_health_status 1" in metrics
            assert "tunward_active_tunnels 4" in metrics
            connections = await self.api(stack, "/api/v1/connections")
            assert {c["verified_device_id"] for c in connections} == {"device-a", "device-b"}
            assert all(c["certificate_sha256"] and c["peer_addr"].startswith("127.0.0.1:") for c in connections)
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await asyncio.gather(*(self.suite.stop(client) for client in stack["clients"]))
            await self.settled(stack)
            assert len((await self.api(stack, "/api/v1/devices"))["devices"]) == 2
            return {"transports": 3, "shared_label_is_not_identity": True, "exact_active_tunnels": 4,
                    "disconnect_and_cancel_cleanup": True, "offline_devices_retained": True}

    async def failed_setup(self):
        async with self.server("failed-setup") as stack:
            for scheme in ("wss", "https", "wts"):
                endpoint = port()
                await self.client(stack, scheme, specs=["-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{self.unused_port}"])
                await self.denied(stack, endpoint)
            assert not await self.api(stack, "/api/v1/clients")
            assert not await self.api(stack, "/api/v1/sessions")
            return {"failed_target_does_not_leave_tunnel_or_label": True, "transports": 3}

    async def reverse(self, scheme):
        async with self.server(f"reverse-{scheme}") as stack:
            fixed = port()
            _, client = await self.client(stack, scheme, label="reverse-owner",
                specs=["-R", f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"])
            for _ in range(150):
                records = await self.api(stack, "/api/v1/sessions")
                listeners = [r for r in records if r["kind"] == "reverse_listener"]
                pending = [r for r in records if r["kind"] == "tunnel" and r["state"] == "pending"]
                if listeners and pending:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError(f"missing pending tunnel or listener: {records}")
            assert len(listeners) == 1 and listeners[0]["assigned_port"] == fixed
            assert all(r["transport"] == scheme and r["verified_device_id"] == "device-a" for r in records)
            await self.held(stack, fixed)
            await self.suite.stop(client)
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await self.settled(stack)
            return {"transport": scheme, "listener_and_pending_tunnel_distinguished": True, "cleanup": True}

    async def persistence(self):
        database = self.suite.out / "restart.sqlite3"
        async with self.server("before-restart", database) as stack:
            for identity in ("a", "b"):
                endpoint, _ = await self.client(stack, "wts", identity)
                await self.held(stack, endpoint)
            before = {d["id"]: d for d in (await self.api(stack, "/api/v1/devices"))["devices"]}
            stack["process"].send_signal(signal.SIGKILL)
            await stack["process"].wait()
        async with self.server("after-restart", database) as stack:
            await self.settled(stack)
            after = {d["id"]: d for d in (await self.api(stack, "/api/v1/devices"))["devices"]}
            assert before.keys() == after.keys()
            assert all(d["active_connections"] == d["active_tunnels"] == 0 for d in after.values())
            endpoint, _ = await self.client(stack, "wts", "rotated-a", "renamed-label")
            await self.held(stack, endpoint)
            rotated = await self.api(stack, "/api/v1/devices/device-a")
            expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.certs / "rotated-a.pem").read_text())).hexdigest()
            assert rotated["first_seen_at"] == before["device-a"]["first_seen_at"]
            assert rotated["observed_connections"] > before["device-a"]["observed_connections"]
            assert rotated["last_certificate_sha256"] == expected
            return {"committed_inventory_survives_sigkill": True, "no_stale_online_counts": True,
                    "same_cn_key_rotation_updates_existing_device": True}

    async def pagination_capacity(self):
        async with self.server("capacity", capacity=2) as stack:
            endpoints = []
            for identity in ("a", "b"):
                endpoint, _ = await self.client(stack, "wts", identity)
                endpoints.append(endpoint)
                await self.held(stack, endpoint)
            before = self.accepted
            endpoint, _ = await self.client(stack, "wts", "c")
            await self.denied(stack, endpoint)
            assert self.accepted == before
            first = await self.api(stack, "/api/v1/devices?limit=1")
            second = await self.api(stack, f'/api/v1/devices?limit=1&after={first["next_cursor"]}')
            assert [d["id"] for d in first["devices"] + second["devices"]] == ["device-a", "device-b"]
            assert second["next_cursor"] is None
            for path in ("?limit=0", "?limit=1001", "?limit=1&limit=2", "?unknown=1"):
                assert (await self.response(stack, "/api/v1/devices" + path))[0] == 400
            assert (await self.response(stack, "/api/v1/devices/unknown"))[0] == 404
            assert (await self.response(stack, "/api/v1/devices", "POST"))[0] == 404
            await self.held(stack, endpoints[0])
            return {"bounded_pagination": True, "new_identity_rejected_at_capacity": True,
                    "known_identity_still_allowed": True, "api_read_only": True}

    async def database_failure(self):
        async with self.server("database-failure") as stack:
            endpoint, _ = await self.client(stack, "wts")
            await self.held(stack, endpoint)
            db = sqlite3.connect(stack["database"], timeout=1)
            try:
                db.execute("BEGIN IMMEDIATE")
                endpoint_b, _ = await self.client(stack, "wts", "b")
                await self.denied(stack, endpoint_b)
                for _ in range(100):
                    status, health = await self.response(stack, "/healthz")
                    if status == 503:
                        break
                    await asyncio.sleep(0.03)
                assert status == 503 and health["inventory_healthy"] is False, health
                await self.api(stack, "/api/v1/devices")
                status, health = await self.response(stack, "/healthz")
                assert status == 503 and health["inventory_healthy"] is False, "read success masked a write failure"
                await self.held(stack, endpoint)
            finally:
                db.rollback()
                db.close()
            await self.held(stack, endpoint_b)
            assert (await self.response(stack, "/healthz"))[0] == 200
            return {"locked_database_denies_new_admission": True, "existing_forwarding_continues": True,
                    "health_degrades_and_recovers": True}

    async def unverified(self):
        async with self.server("unverified", cleartext=True) as stack:
            for scheme in ("ws", "http"):
                endpoint, _ = await self.client(stack, scheme, label="device-a")
                await self.held(stack, endpoint)
            records = await self.api(stack, "/api/v1/connections")
            assert records and all(r["verified_device_id"] is None for r in records)
            assert (await self.response(stack, "/api/v1/devices"))[0] == 503
            clients = await self.api(stack, "/api/v1/clients")
            assert len(clients) == 1 and clients[0]["active_tunnels"] == 2
            return {"cleartext_labels_never_become_verified_devices": True, "ws_http_parity": True}

    async def startup(self):
        database = self.suite.out / "foreign.sqlite3"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE keep(value TEXT)")
            db.execute("INSERT INTO keep VALUES ('preserve')")
        database.chmod(0o600)
        for name, scheme, db in (("foreign", "wss", database), ("cleartext", "ws", self.suite.out / "clear.sqlite3")):
            process = await self.suite.spawn(f"invalid-{name}", "server", f"{scheme}://127.0.0.1:{port()}",
                "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--fleet-inventory", str(db))
            assert await asyncio.wait_for(process.wait(), 5) != 0
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT value FROM keep").fetchone()[0] == "preserve"
        async with self.server("owner") as stack:
            process = await self.suite.spawn("second-inventory-owner", "server", f"wss://127.0.0.1:{port()}",
                "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--fleet-inventory", str(stack["database"]))
            assert await asyncio.wait_for(process.wait(), 5) != 0
        return {"foreign_database_preserved": True, "cleartext_rejected": True, "second_owner_rejected": True}

    async def run(self):
        await self.prepare()
        try:
            for name, case in [("transport-parity-and-cleanup", self.parity), ("failed-setup", self.failed_setup),
                *[(f"reverse-{s}", lambda s=s: self.reverse(s)) for s in ("wss", "https", "wts")],
                ("restart-and-key-rotation", self.persistence), ("capacity-and-pagination", self.pagination_capacity),
                ("database-write-failure", self.database_failure), ("unverified-labels", self.unverified),
                ("startup-and-ownership", self.startup)]:
                await self.suite.check(f"fleet-inventory/{name}", case, 60)
        finally:
            await asyncio.gather(*(self.suite.stop(p) for p in self.suite.processes))
            self.target.close()
            await self.target.wait_closed()
            self.udp.close()
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "synthetic Linux loopback; local SQLite inventory of observed verified CNs; not enrollment or clustered state",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(FleetChecks(parser.parse_args()).run())))
