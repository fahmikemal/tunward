#!/usr/bin/env python3
"""Bounded synthetic mTLS tenant/RBAC, resource ownership and cross-transport checks."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import random
import socket

from qualify import close, port
from qualify_quotas import QuotaChecks
from qualify_wan import command

PERMISSIONS = ["forward_tcp", "forward_udp", "reverse_tcp", "reverse_udp", "reverse_socks5", "reverse_http_proxy", "reverse_unix"]


class TenantChecks(QuotaChecks):
    async def prepare(self):
        await super().prepare()
        for serial, identity in enumerate(("c", "unknown"), 701):
            await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                          "-subj", f"/CN=device-{identity}", "-keyout", self.certs / f"{identity}.key", "-out", self.certs / f"{identity}.csr")
            await command("openssl", "x509", "-req", "-in", self.certs / f"{identity}.csr", "-CA", self.certs / "ca.pem",
                          "-CAkey", self.certs / "ca.key", "-set_serial", serial, "-days", 4,
                          "-extfile", self.certs / "client.ext", "-out", self.certs / f"{identity}.pem")
            (self.certs / f"{identity}.key").chmod(0o600)
        self.other_target = await asyncio.start_server(self.echo, "127.0.0.1", 0)
        self.other_port = self.other_target.sockets[0].getsockname()[1]
        self.pools = self.free_pool(), self.free_pool()
        while abs(self.pools[0] - self.pools[1]) < 32:
            self.pools = self.free_pool(), self.free_pool()

    @staticmethod
    def free_pool():
        for _ in range(200):
            base = random.randrange(12000, 28000, 32)
            sockets = []
            try:
                for endpoint in range(base, base + 32):
                    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                        probe = socket.socket(type=kind)
                        sockets.append(probe)
                        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        probe.bind(("127.0.0.1", endpoint))
                return base
            except OSError:
                pass
            finally:
                for probe in sockets:
                    probe.close()
        raise RuntimeError("no bounded loopback port pool available")

    def make_policy(self, alpha_unix, beta_unix, c_agent=False):
        return {"version": 1, "roles": {"agent": PERMISSIONS, "reader": ["forward_tcp"]}, "tenants": {
            name: {"restrictions": [f"{name}-forward", f"{name}-reverse", "management"],
                   "reverse_bindings": [{"address": "127.0.0.1", "ports": [f"{base}..{base + 31}"], "allow_ephemeral": True}],
                   "reverse_unix_paths": [str(unix)]}
            for name, base, unix in (("alpha", self.pools[0], alpha_unix), ("beta", self.pools[1], beta_unix))},
            "devices": {"device-a": {"tenant": "alpha", "roles": ["agent"]},
                        "device-b": {"tenant": "beta", "roles": ["agent"]},
                        "device-c": {"tenant": "alpha", "roles": ["agent" if c_agent else "reader"]}}}

    @asynccontextmanager
    async def server(self, label, enabled=True, c_agent=False, combined=False):
        self.serial += 1
        prefix = f"{self.serial}-{label}"
        sp, mp = port(), port()
        alpha_unix, beta_unix = [self.suite.out / f"{self.serial}-{name}.sock" for name in ("a", "b")]
        tenant_file = self.suite.out / f"{prefix}-tenants.json"
        tenant_file.write_text(json.dumps(self.make_policy(alpha_unix, beta_unix, c_agent)))
        restrictions = self.suite.out / f"{prefix}-restrictions.yaml"
        rules = "restrictions:\n"
        for name, target in (("alpha", self.target_port), ("beta", self.other_port)):
            rules += f"""  - name: {name}-forward
    match: [Any]
    allow:
      - !Tunnel
        protocol: [Tcp, Udp]
        port: ["{target}", "{self.udp_port}", "{self.unused_port}"]
        cidr: [127.0.0.1/32]
  - name: {name}-reverse
    match: [Any]
    allow:
      - !ReverseTunnel
        protocol: [Tcp, Udp, Socks5, HttpProxy, Unix]
        cidr: [127.0.0.1/32]
        port_mapping: ["42:{self.pools[1]}", "43:{self.pools[0] + 2}"]
"""
        rules += f"""  - name: management
    match: [Any]
    allow:
      - !Tunnel
        protocol: [Tcp]
        port: ["{mp}"]
        cidr: [127.0.0.1/32]
"""
        restrictions.write_text(rules)
        options = ["--tenant-config", str(tenant_file)] if enabled else []
        revocations = self.suite.out / f"{prefix}-revocations.json"
        if combined:
            quotas = self.suite.out / f"{prefix}-quotas.json"
            quotas.write_text(json.dumps({"version": 1, "default": {"max_sessions": 16, "max_tunnels": 1}}))
            revocations.write_text('{"version":1}')
            options += ["--device-quota-config", str(quotas), "--device-revocation-config", str(revocations)]
        process = await self.suite.spawn(prefix, "server", f"wts://127.0.0.1:{sp}",
            "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
            "--tls-client-ca-certs", str(self.certs / "ca.pem"), "--restrict-config", str(restrictions), *options,
            "--management-api", f"127.0.0.1:{mp}", "--fleet-inventory", str(self.suite.out / f"{prefix}.sqlite3"),
            "--websocket-ping-frequency", "1s", "--remote-to-local-server-idle-timeout", "3s")
        stack = {"port": sp, "management": mp, "prefix": prefix, "clients": [], "writers": [],
                 "alpha_unix": alpha_unix, "beta_unix": beta_unix, "tenant_file": tenant_file,
                 "restrictions": restrictions, "revocations": revocations}
        try:
            await self.suite.ready(mp, process)
            yield stack
        finally:
            await asyncio.gather(*(close(writer) for writer in stack["writers"]))
            await asyncio.gather(*(self.suite.stop(client) for client in stack["clients"]))
            await self.suite.stop(process)

    async def api(self, stack, route):
        return await self.suite.api(stack["management"], route)

    async def forward(self, stack, scheme, identity="a", target=None, headers=()):
        endpoint = port()
        await self.client(stack, scheme, identity, "same-label", ["-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{target or self.target_port}"], headers)
        return endpoint

    async def parity_and_scope(self):
        async with self.server("scope") as stack:
            for scheme in ("wss", "https", "wts"):
                for identity, target in (("a", self.target_port), ("b", self.other_port), ("c", self.target_port)):
                    endpoint = await self.forward(stack, scheme, identity, target)
                    await self.held(stack, endpoint)
                before = self.accepted
                for identity, target in (("a", self.other_port), ("b", self.target_port), ("unknown", self.target_port)):
                    endpoint = await self.forward(stack, scheme, identity, target)
                    await self.denied(stack, endpoint)
                assert self.accepted == before, "tenant denial opened an unauthorized target"
            connections = await self.api(stack, "/api/v1/connections")
            assert all(record["tenant_id"] == ("beta" if record["verified_device_id"] == "device-b" else "alpha") for record in connections)
            assert all(record["roles"] == (["reader"] if record["verified_device_id"] == "device-c" else ["agent"]) for record in connections)
            assert "device-unknown" not in {record["id"] for record in (await self.api(stack, "/api/v1/devices"))["devices"]}
            sessions = await self.api(stack, "/api/v1/sessions")
            assert len(sessions) == 9 and all(record["tenant_id"] for record in sessions)
            return {"transports": 3, "cross_tenant_destinations_denied_before_target": True,
                    "unknown_verified_identity_denied": True, "trusted_tenant_and_role_metadata": True}

    async def spoofing_and_management(self):
        async with self.server("spoofing") as stack:
            for scheme in ("wss", "https", "wts"):
                headers = ["-H", "X-Tenant-Id: beta", "-H", "X-Role: agent", "-H", "X-Forwarded-For: 203.0.113.9"]
                endpoint = await self.forward(stack, scheme, "a", self.other_port, headers)
                await self.denied(stack, endpoint)
                endpoint = await self.forward(stack, scheme, "a", stack["management"])
                await self.denied(stack, endpoint)
                endpoint = await self.forward(stack, scheme, "a", self.target_port, headers)
                await self.held(stack, endpoint)
            records = await self.api(stack, "/api/v1/connections")
            assert all(record["tenant_id"] == "alpha" and record["peer_addr"].startswith("127.0.0.1:") for record in records)
            endpoint = await self.forward(stack, "wts", "rotated-a")
            await self.held(stack, endpoint)
            return {"headers_labels_and_rotation_do_not_select_tenant": True, "management_port_reserved": True}

    async def wait_listener(self, stack, label):
        for _ in range(200):
            records = await self.api(stack, "/api/v1/sessions")
            listeners = [r for r in records if r["kind"] == "reverse_listener" and r["client_id"] == label]
            if listeners:
                return listeners[0]
            await asyncio.sleep(0.02)
        raise AssertionError(f"no reverse listener for {label}")

    async def rejected_reverse(self, stack, scheme, identity, spec, label="denied"):
        _, process = await self.client(stack, scheme, identity, label, ["-R", spec])
        await asyncio.sleep(0.2)
        assert not [r for r in await self.api(stack, "/api/v1/sessions") if r["client_id"] == label], "denied reverse work left a resource"
        await self.suite.stop(process)

    async def reverse_and_roles(self, scheme):
        async with self.server(f"reverse-{scheme}") as stack:
            fixed = self.pools[0]
            spec = f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"
            await self.client(stack, scheme, "a", "owner", ["-R", spec])
            listener = await self.wait_listener(stack, "owner")
            assert listener["tenant_id"] == "alpha" and listener["assigned_port"] == fixed
            await self.rejected_reverse(stack, scheme, "b", spec, "other-tenant")
            await self.rejected_reverse(stack, scheme, "c", spec, "no-agent-role")
            await self.held(stack, fixed)
            await self.rejected_reverse(stack, scheme, "a", f"tcp://127.0.0.1:42:127.0.0.1:{self.target_port}", "mapped-outside")
            assert not self.bound(self.pools[1]), "port mapping allocated another tenant's reservation"
            return {"transport": scheme, "cross_tenant_reverse_denied": True, "missing_role_denied": True, "mapped_port_checked": True}

    async def device_ownership(self, enabled):
        async with self.server("device-owner", enabled=enabled, c_agent=True) as stack:
            fixed = self.pools[0] + 1
            spec = f"tcp://127.0.0.1:{fixed}:127.0.0.1:{self.target_port}"
            await self.client(stack, "wss", "a", "owner", ["-R", spec])
            await self.wait_listener(stack, "owner")
            await self.rejected_reverse(stack, "wts", "c", spec, "other-device")
            await self.held(stack, fixed)
            return {"tenant_mode": enabled, "different_verified_device_cannot_reuse_cached_listener": True,
                    "quotas_and_revocation_not_required": True}

    async def ephemeral_protocols(self):
        async with self.server("ephemeral") as stack:
            for scheme in ("wss", "https", "wts"):
                for protocol, mode, target in (("tcp", "tcp", self.target_port), ("udp", "udp", self.udp_port),
                                               ("socks5", "socks", None), ("http", "http", None)):
                    label = f"{scheme}-{protocol}"
                    spec = f"{protocol}://127.0.0.1:0" + (f":127.0.0.1:{target}" if target else "")
                    await self.client(stack, scheme, "a", label, ["-R", spec])
                    listener = await self.wait_listener(stack, label)
                    endpoint = listener["assigned_port"]
                    assert self.pools[0] <= endpoint < self.pools[0] + 32, listener
                    if mode == "udp":
                        await self.suite.udp(endpoint, 1200, 4)
                    else:
                        await self.suite.exchange(mode, endpoint, 1024)
            return {"transports": 3, "reverse_protocols": ["tcp", "udp", "socks5", "http"],
                    "port_zero_allocations_stay_inside_owned_pool": True}

    async def unix(self):
        async with self.server("unix") as stack:
            for identity, path, allowed in (("a", stack["beta_unix"], False), ("c", stack["alpha_unix"], False),
                                             ("a", stack["alpha_unix"], True)):
                spec = f"unix://{path}:127.0.0.1:{self.target_port}"
                if not allowed:
                    await self.rejected_reverse(stack, "wts", identity, spec)
                    assert not path.exists(), "denial created a Unix filesystem entry"
                else:
                    await self.client(stack, "wts", identity, "unix-owner", ["-R", spec])
                    listener = await self.wait_listener(stack, "unix-owner")
                    assert listener["tenant_id"] == "alpha"
                    await self.suite.exchange("unix", str(path), 1024)
            return {"unix_exact_reservations": True, "role_required": True, "denial_has_no_filesystem_side_effect": True}

    async def combined(self):
        async with self.server("combined", combined=True) as stack:
            endpoint = await self.forward(stack, "wts")
            reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
            stack["writers"].append(writer)
            writer.write(b"hello")
            await writer.drain()
            assert await reader.readexactly(5) == b"hello"
            await self.denied(stack, endpoint)
            temporary = stack["revocations"].with_suffix(".new")
            temporary.write_text('{"version":1,"blocked_devices":["device-a"]}')
            temporary.replace(stack["revocations"])
            assert await asyncio.wait_for(reader.read(1), 5) == b""
            endpoint = await self.forward(stack, "wts", "b", self.other_port)
            await self.held(stack, endpoint)
            assert all(r["verified_device_id"] != "device-a" for r in await self.api(stack, "/api/v1/connections"))
            return {"tenant_quotas_revocation_and_inventory_together": True, "revoked_tenant_work_cleared": True}

    async def startup(self):
        alpha, beta = [self.suite.out / f"startup-{name}.sock" for name in ("a", "b")]
        original = self.make_policy(alpha, beta)
        restrictions = self.suite.out / "startup-restrictions.yaml"
        restrictions.write_text("restrictions:\n" + "".join(f" - name: {name}\n   match: [Any]\n   allow: []\n" for name in ("alpha-forward", "alpha-reverse", "beta-forward", "beta-reverse", "management")))
        for name in ("overlap", "unknown-role", "typo", "cleartext", "missing-ca", "missing-restrictions"):
            policy = json.loads(json.dumps(original))
            if name == "overlap": policy["tenants"]["beta"]["reverse_bindings"] = policy["tenants"]["alpha"]["reverse_bindings"]
            if name == "unknown-role": policy["devices"]["device-a"]["roles"] = ["admin"]
            if name == "typo": policy["tenants"]["alpha"]["reverse_binding"] = []
            config = self.suite.out / f"startup-{name}.json"
            config.write_text(json.dumps(policy))
            options = [] if name == "missing-ca" else ["--tls-client-ca-certs", str(self.certs / "ca.pem")]
            if name != "missing-restrictions": options += ["--restrict-config", str(restrictions)]
            process = await self.suite.spawn(f"startup-{name}", "server", f'{"ws" if name == "cleartext" else "wss"}://127.0.0.1:{port()}',
                "--tls-certificate", str(self.certs / "server.pem"), "--tls-private-key", str(self.certs / "server.key"),
                "--tenant-config", str(config), *options)
            assert await asyncio.wait_for(process.wait(), 5) != 0, name
        return {"overlapping_resources_unknown_roles_typos_and_missing_trust_rejected": True}

    async def run(self):
        await self.prepare()
        try:
            cases = [("forward-scope-and-metadata", self.parity_and_scope), ("spoofing-and-management", self.spoofing_and_management),
                     *[(f"reverse-{s}", lambda s=s: self.reverse_and_roles(s)) for s in ("wss", "https", "wts")],
                     ("device-owner-with-policy", lambda: self.device_ownership(True)),
                     ("device-owner-without-policy", lambda: self.device_ownership(False)),
                     ("ephemeral-reverse-protocols", self.ephemeral_protocols), ("unix-scope", self.unix),
                     ("quotas-revocation-inventory", self.combined), ("startup-validation", self.startup)]
            for name, case in cases:
                await self.suite.check(f"tenants/{name}", case, 90)
        finally:
            await asyncio.gather(*(self.suite.stop(process) for process in self.suite.processes))
            self.target.close()
            self.other_target.close()
            await asyncio.gather(self.target.wait_closed(), self.other_target.wait_closed())
            self.udp.close()
            (self.suite.out / "metadata.json").write_text(json.dumps({
                "binary_sha256": hashlib.sha256(self.suite.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "synthetic Linux loopback; tunnel RBAC and reverse ownership; not management-API tenant authentication or OS/network isolation",
            }, indent=2) + "\n")
        return any(row["status"] == "fail" for row in self.suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(TenantChecks(parser.parse_args()).run())))
