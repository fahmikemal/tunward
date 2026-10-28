#!/usr/bin/env python3
"""Bounded, loopback-only mTLS identity, ACL, registry-label and quota qualification."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from qualify import Suite, close, port
from qualify_wan import certificates, command, echo


async def run(args):
    suite = Suite(args)
    certs = suite.out / "certificates"
    await certificates(certs, "127.0.0.1")
    subjects = {
        "device-a": ("/CN=device-a", None),
        "device-b": ("/CN=device-b", None),
        "no-cn": ("/O=Qualification", None),
        "multiple-cn": ("/CN=device-a/CN=device-b", None),
        "device-san-uri": ("/CN=ignored-cn", "subjectAltName=URI:spiffe://example.org/ns/prod/sa/device-san"),
        "device-san-dns": ("/CN=ignored-cn", "subjectAltName=DNS:device-san.corp.internal"),
        "device-san-multi-uri": ("/CN=ignored-cn", "subjectAltName=URI:spiffe://example.org/sa/1,URI:spiffe://example.org/sa/2"),
        "device-san-multi-dns": ("/CN=ignored-cn", "subjectAltName=DNS:d1.corp.internal,DNS:d2.corp.internal"),
    }
    for serial, (name, (subject, custom_san)) in enumerate(subjects.items(), 201):
        await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", subject, "-keyout", certs / f"{name}.key", "-out", certs / f"{name}.csr")
        if custom_san:
            ext_file = certs / f"{name}.ext"
            ext_file.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                f"extendedKeyUsage=clientAuth\n{custom_san}\n")
        else:
            ext_file = certs / "client.ext"
        await command("openssl", "x509", "-req", "-in", certs / f"{name}.csr", "-CA", certs / "ca.pem",
                      "-CAkey", certs / "ca.key", "-set_serial", str(serial), "-days", "4",
                      "-extfile", ext_file, "-out", certs / f"{name}.pem")
        (certs / f"{name}.key").chmod(0o600)
    targets = [await asyncio.start_server(echo, "127.0.0.1", 0) for _ in range(4)]
    a, b, c, d = [target.sockets[0].getsockname()[1] for target in targets]
    policy = suite.out / "restrictions.yaml"
    policy.write_text("restrictions:\n" + "".join(
        f"  - name: {device}\n    match:\n      - !PathPrefix '^{device}$'\n"
        f"    allow:\n      - !Tunnel\n        protocol: [Tcp]\n        port: [{target}]\n"
        "        cidr: [127.0.0.1/32]\n" for device, target in (
            ("device-a", a),
            ("device-b", b),
            (r"spiffe://example\.org/ns/prod/sa/device-san", c),
            (r"device-san\.corp\.internal", d),
        )))
    metadata = {"binary_sha256": hashlib.sha256(suite.binary.read_bytes()).hexdigest(), "max_held_tunnels": 32,
                "scope": "local synthetic CA and targets only; no production identities", "args": vars(args)}
    (suite.out / "metadata.json").write_text(json.dumps(metadata, indent=2))
    try:
        for scheme in ("wss", "https", "wts"):
            sp, mp = port(), port()
            server = await suite.spawn(f"identity-{scheme}-server", "server", f"wts://127.0.0.1:{sp}",
                                       "--tls-certificate", str(certs / "server.pem"), "--tls-private-key", str(certs / "server.key"),
                                       "--tls-client-ca-certs", str(certs / "ca.pem"), "--restrict-config", str(policy),
                                       "--management-api", f"127.0.0.1:{mp}")
            clients = []
            await suite.ready(sp, server)
            async def start_client(label, identity, prefix, target, client_id="claimed-label", id_field=None, s_port=sp, s_scheme=scheme):
                lp = port()
                options = [] if identity is None else ["--tls-certificate", str(certs / f"{identity}.pem"),
                                                       "--tls-private-key", str(certs / f"{identity}.key")]
                if id_field:
                    options.extend(["--tls-client-identity-field", id_field])
                prefix_args = ["-P", prefix] if prefix is not None else []
                client = await suite.spawn(f"identity-{s_scheme}-{label}", "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{target}",
                                           *prefix_args, "--client-id", client_id, "--connection-retry-max-backoff", "1s",
                                           "--tls-verify-certificate", *options, f"{s_scheme}://127.0.0.1:{s_port}",
                                           extra_env={"SSL_CERT_FILE": str(certs / "ca.pem"), "SSL_CERT_DIR": ""})
                clients.append(client)
                await suite.ready(lp, client)
                return lp
            async def case(label, identity, prefix, target, allowed, id_field=None, s_port=sp, s_scheme=scheme):
                lp = await start_client(label, identity, prefix, target, id_field=id_field, s_port=s_port, s_scheme=s_scheme)
                try:
                    await asyncio.wait_for(suite.exchange("tcp", lp), 3)
                    success = True
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    success = False
                assert success == allowed, f"observed_access={success}, expected={allowed}"
                return {"observed_access": success}
            try:
                for label, identity, prefix, target, allowed in (
                    ("a-own-target", "device-a", "device-a", a, True),
                    ("b-own-target", "device-b", "device-b", b, True),
                    ("a-other-target", "device-a", "device-a", b, False),
                    ("a-claims-b-path", "device-a", "device-b", b, False),
                    ("missing-certificate", None, "device-b", b, False),
                    ("no-cn-claims-b-path", "no-cn", "device-b", b, False),
                    ("multiple-cn-claims-a-path", "multiple-cn", "device-a", a, False),
                ):
                    await suite.check(f"identity/{scheme}/{label}", lambda l=label, i=identity, p=prefix, t=target, ok=allowed:
                                      case(l, i, p, t, ok), 6)
                lp = await start_client("holds", "device-a", "device-a", a, "spoofed-device-b")
                held = []
                try:
                    for _ in range(32):
                        r, w = await suite.connect("tcp", lp)
                        w.write(b"held")
                        await w.drain()
                        assert await asyncio.wait_for(r.readexactly(4), 3) == b"held"
                        held.append((r, w))
                    suite.record(f"identity/{scheme}/held-tunnel-observation", held_tunnels=32,
                                 certificate_identity="device-a", supplied_label="spoofed-device-b",
                                 note="This observes accepted load; it does not validate a quota because no device quota is configured.")
                    if scheme == "wss":
                        records = await suite.api(mp, "/api/v1/clients")
                        suite.record("identity/registry-label-observation", clients=records,
                                     note="Header labels are caller-controlled. ACL tests independently verify certificate/path enforcement.")
                finally:
                    for _, writer in held:
                        suite.owned_writers.discard(writer)
                        await close(writer)
            finally:
                await asyncio.gather(*(suite.stop(client) for client in clients))
                await suite.stop(server)

        # Dedicated qualification for SAN-URI (SPIFFE) and SAN-DNS across mTLS
        for id_field, cert_name, target_port, wrong_cert in (
            ("san-uri", "device-san-uri", c, "device-san-multi-uri"),
            ("san-dns", "device-san-dns", d, "device-san-multi-dns"),
        ):
            sp = port()
            server = await suite.spawn(f"identity-pki-{id_field}-server", "server", f"wss://127.0.0.1:{sp}",
                                       "--tls-certificate", str(certs / "server.pem"), "--tls-private-key", str(certs / "server.key"),
                                       "--tls-client-ca-certs", str(certs / "ca.pem"), "--restrict-config", str(policy),
                                       "--tls-client-identity-field", id_field)
            clients = []
            await suite.ready(sp, server)
            try:
                # 1. Valid SAN extraction (auto-derived path from leaf certificate)
                await suite.check(f"identity/pki/{id_field}/auto-derive-success",
                                  lambda f=id_field, c=cert_name, t=target_port: case(f"{f}-auto", c, None, t, True, id_field=f, s_port=sp, s_scheme="wss"), 6)
                # 2. Accessing forbidden target with verified SAN identity
                await suite.check(f"identity/pki/{id_field}/forbidden-target-rejected",
                                  lambda f=id_field, c=cert_name: case(f"{f}-forbidden", c, None, a, False, id_field=f, s_port=sp, s_scheme="wss"), 6)
                # 3. Presenting certificate with multiple SANs of requested type -> rejected
                await suite.check(f"identity/pki/{id_field}/multiple-sans-rejected",
                                  lambda f=id_field, w=wrong_cert, t=target_port: case(f"{f}-multi", w, None, t, False, id_field=f, s_port=sp, s_scheme="wss"), 6)
                # 4. Presenting CN-only certificate when server expects SAN -> rejected
                await suite.check(f"identity/pki/{id_field}/missing-san-rejected",
                                  lambda f=id_field, t=target_port: case(f"{f}-missing-san", "device-a", None, t, False, id_field=f, s_port=sp, s_scheme="wss"), 6)
            finally:
                await asyncio.gather(*(suite.stop(client) for client in clients))
                await suite.stop(server)
        suite.record("identity/device-quota-enforcement", "not_run",
                     reason="Quotas are disabled in this identity suite. Run scripts/qualify_quotas.py to verify configured enforcement.")
    finally:
        await asyncio.gather(*(suite.stop(p) for p in suite.processes))
        for target in targets:
            target.close()
            await target.wait_closed()
    return any(row["status"] == "fail" for row in suite.results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(run(parser.parse_args()))))


if __name__ == "__main__":
    main()
