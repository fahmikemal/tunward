#!/usr/bin/env python3
"""Bounded synthetic verified-device session admission and inventory; no physical MDM devices."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import ssl

from qualify import close, port
from qualify_quotas import QuotaChecks
from qualify_wan import command


class DeviceScaleChecks(QuotaChecks):
    async def run(self):
        await self.prepare()
        identities = [f"synthetic-{n:04d}" for n in range(self.suite.args.devices)]
        semaphore = asyncio.Semaphore(8)
        async def issue(index, identity):
            async with semaphore:
                key, csr, cert = [self.certs / f"{identity}.{suffix}" for suffix in ("key", "csr", "pem")]
                await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-subj", f"/CN={identity}", "-keyout", key, "-out", csr)
                await command("openssl", "x509", "-req", "-in", csr, "-CA", self.certs / "ca.pem", "-CAkey", self.certs / "ca.key",
                    "-set_serial", 1000 + index, "-days", 4, "-extfile", self.certs / "client.ext", "-out", cert)
                key.chmod(0o600)
        await asyncio.gather(*(issue(n, identity) for n, identity in enumerate(identities)))
        endpoint, management = port(), port()
        tenant = self.suite.out / "tenants.json"
        tenant.write_text(json.dumps({"version": 1, "roles": {"reader": ["forward_tcp"]},
            "tenants": {"synthetic": {"restrictions": ["Synthetic quota identities"]}},
            "devices": {identity: {"tenant": "synthetic", "roles": ["reader"]} for identity in identities}}))
        quota = self.suite.out / "quotas.json"
        quota.write_text('{"version":1,"default":{"max_sessions":1,"max_tunnels":4}}')
        server = await self.suite.spawn("device-scale-server", "server", f"wss://127.0.0.1:{endpoint}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(self.policy),
            "--tenant-config", str(tenant), "--device-quota-config", str(quota),
            "--fleet-inventory", str(self.suite.out / "devices.sqlite3"), "--management-api", f"127.0.0.1:{management}")
        connections = []
        try:
            await self.suite.ready(management, server)
            admission = asyncio.Semaphore(16)
            async def connect(identity):
                async with admission:
                    context = ssl.create_default_context(cafile=self.certs / "ca.pem")
                    context.load_cert_chain(self.certs / f"{identity}.pem", self.certs / f"{identity}.key")
                    connection = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", endpoint, ssl=context), 10)
                    connections.append(connection)
                    return connection
            await asyncio.gather(*(connect(identity) for identity in identities))
            async def wait_count(expected):
                for _ in range(100):
                    records = await self.suite.api(management, "/api/v1/connections")
                    if len(records) == expected:
                        return records
                    await asyncio.sleep(0.05)
                raise AssertionError(f"expected {expected} active sessions, observed {len(records)}")
            records = await wait_count(len(identities))
            assert {r["verified_device_id"] for r in records} == set(identities)
            assert all(r["tenant_id"] == "synthetic" and r["roles"] == ["reader"] for r in records)
            self.suite.record("device-scale/verified-session-admission", distinct_verified_identities=len(identities),
                              authenticated_tls_sessions=len(records), physical_devices=0, application_tunnels=0)
            reader, writer = await connect(identities[0])
            assert await asyncio.wait_for(reader.read(1), 3) == b""
            await close(writer)
            await wait_count(len(identities))
            self.suite.record("device-scale/per-identity-session-cap", second_session_denied=True)
            devices = (await self.suite.api(management, f"/api/v1/devices?limit={len(identities)}"))["devices"]
            assert len(devices) == len(identities) and all(d["active_connections"] == 1 for d in devices)
            self.suite.record("device-scale/inventory", distinct_rows=len(devices), all_online=True)
            await asyncio.gather(*(close(w) for _, w in connections))
            connections.clear()
            await wait_count(0)
            devices = (await self.suite.api(management, f"/api/v1/devices?limit={len(identities)}"))["devices"]
            assert len(devices) == len(identities) and all(d["active_connections"] == 0 for d in devices)
            self.suite.record("device-scale/disconnect-cleanup", persistent_rows_retained=True, live_connections=0)
        except Exception as exc:
            self.suite.record("device-scale/suite", "fail", error=f"{type(exc).__name__}: {exc}")
        finally:
            await asyncio.gather(*(close(w) for _, w in connections))
            await self.suite.stop(server)
            self.target.close()
            await self.target.wait_closed()
            self.udp.close()
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "devices": len(identities), "physical_devices": 0,
                "scope": "synthetic distinct-CN idle TLS admission, tenant tags, quota and inventory; not WebSocket upgrades, concurrent application tunnels, WT sessions, or real MDM lifecycle"
            }, indent=2) + "\n")
        return any(r["status"] == "fail" for r in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    parser.add_argument("--devices", type=int, default=200)
    args = parser.parse_args()
    if not 1 <= args.devices <= 256:
        parser.error("devices must be 1..256")
    raise SystemExit(bool(asyncio.run(DeviceScaleChecks(args).run())))
