#!/usr/bin/env python3
"""Reproduce pool exhaustion with a bounded TLS handshake delay on loopback."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import time

from qualify import Suite, close, port
from qualify_wan import certificates, echo


async def run(args):
    suite = Suite(args)
    certs = suite.out / "certificates"
    await certificates(certs, "127.0.0.1")
    target = await asyncio.start_server(echo, "127.0.0.1", 0)
    suite.echo_port = target.sockets[0].getsockname()[1]
    server_port = port()
    policy = suite.out / "restrictions.yaml"
    policy.write_text("restrictions:\n  - name: Pool deadline control\n    match:\n"
                      "      - !PathPrefix '^v1$'\n    allow:\n      - !Tunnel\n"
                      f"        protocol: [Tcp]\n        port: [{suite.echo_port}]\n        cidr: [127.0.0.1/32]\n")
    tasks = set()
    async def delayed(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        upstream = None
        try:
            # Delay TLS establishment without terminating or replacing TLS.
            await asyncio.sleep(4)
            remote, upstream = await asyncio.open_connection("127.0.0.1", server_port)
            async def pump(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            a = asyncio.create_task(pump(reader, upstream))
            b = asyncio.create_task(pump(remote, writer))
            try:
                await asyncio.wait((a, b), return_when=asyncio.FIRST_COMPLETED)
            finally:
                a.cancel()
                b.cancel()
                await asyncio.gather(a, b, return_exceptions=True)
        except OSError:
            pass
        finally:
            if upstream:
                await close(upstream)
            await close(writer)
            tasks.discard(task)
    proxy = await asyncio.start_server(delayed, "127.0.0.1", 0)
    proxy_port = proxy.sockets[0].getsockname()[1]
    (suite.out / "metadata.json").write_text(json.dumps({
        "binary_sha256": hashlib.sha256(suite.binary.read_bytes()).hexdigest(),
        "tls_handshake_delay_seconds": 4, "connections_per_case": 4,
        "scope": "loopback-only synthetic CA, no packet injection or firewall changes"}, indent=2))
    try:
        server = await suite.spawn("pool-control-server", "server", f"wss://127.0.0.1:{server_port}",
                                   "--tls-certificate", str(certs / "server.pem"), "--tls-private-key", str(certs / "server.key"),
                                   "--tls-client-ca-certs", str(certs / "ca.pem"), "--restrict-config", str(policy))
        await suite.ready(server_port, server)
        for deadline, expected in ((3, False), (20, True)):
            label = f"pool-{deadline}"
            lp = port()
            process = await suite.spawn(label, "client", "-L", f"tcp://127.0.0.1:{lp}:127.0.0.1:{suite.echo_port}",
                                        "--connection-retry-max-backoff", f"{deadline}s", "--tls-verify-certificate",
                                        "--tls-certificate", str(certs / "client.pem"), "--tls-private-key", str(certs / "client.key"),
                                        f"https://127.0.0.1:{proxy_port}",
                                        extra_env={"SSL_CERT_FILE": str(certs / "ca.pem"), "SSL_CERT_DIR": ""})
            try:
                # A TCP readiness probe would itself consume a connection-pool slot.
                for _ in range(300):
                    listeners = Path("/proc/net/tcp").read_text().splitlines()[1:]
                    if any(int(row.split()[1].rsplit(":", 1)[1], 16) == lp and row.split()[3] == "0A"
                           for row in listeners):
                        break
                    if process.returncode is not None:
                        raise RuntimeError("client exited before listening")
                    await asyncio.sleep(0.01)
                else:
                    raise TimeoutError("client did not start listening")
                async def case():
                    started = time.monotonic()
                    outcomes = await asyncio.gather(*(asyncio.wait_for(suite.exchange("tcp", lp), 12)
                                                      for _ in range(4)), return_exceptions=True)
                    errors = [type(item).__name__ for item in outcomes if isinstance(item, BaseException)]
                    log = (suite.out / f"{label}.log").read_text()
                    pool_timeouts = log.count("from the pool: TimedOut")
                    assert len(errors) == (0 if expected else 4), errors
                    assert pool_timeouts == (0 if expected else 4), log
                    if not expected:
                        assert errors == ["IncompleteReadError"] * 4, errors
                    return {"expected_access": expected, "errors": errors, "pool_timeouts": pool_timeouts,
                            "exchange_seconds": round(time.monotonic() - started, 3)}
                await suite.check(f"pool-control/deadline-{deadline}", case, 15)
            finally:
                await suite.stop(process)
    finally:
        proxy.close()
        await proxy.wait_closed()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)
        await asyncio.gather(*(suite.stop(p) for p in suite.processes))
        target.close()
        await target.wait_closed()
    return any(row["status"] == "fail" for row in suite.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=True)
    raise SystemExit(bool(asyncio.run(run(parser.parse_args()))))
