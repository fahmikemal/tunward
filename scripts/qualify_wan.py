#!/usr/bin/env python3
"""Authenticated WAN checks against a disposable staging agent; never changes firewall rules."""

import argparse
import asyncio
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import ssl
import tarfile
import time
import uuid

from qualify import EchoUDP, Suite, close, port


async def command(*argv, timeout=20):
    process = await asyncio.create_subprocess_exec(*map(str, argv), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    if process.returncode:
        raise RuntimeError(f"{argv[0]} exited {process.returncode}: {stderr.decode(errors='replace')[:500]}")
    return stdout


async def certificates(directory, address):
    directory.mkdir(mode=0o700)
    await command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                  "-days", "4", "-subj", "/CN=Disposable WAN Qualification CA", "-addext", "basicConstraints=critical,CA:TRUE",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                  "-keyout", directory / "ca.key", "-out", directory / "ca.pem")
    for name, cn, usage in (("server", "localhost", "serverAuth"), ("client", "v1", "clientAuth")):
        await command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", f"/CN={cn}", "-keyout", directory / f"{name}.key", "-out", directory / f"{name}.csr")
        extension = directory / f"{name}.ext"
        extension.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\n"
                             f"subjectAltName=IP:{address},DNS:localhost\n")
        await command("openssl", "x509", "-req", "-in", directory / f"{name}.csr", "-CA", directory / "ca.pem",
                      "-CAkey", directory / "ca.key", "-set_serial", "101" if name == "server" else "102", "-days", "4",
                      "-extfile", extension, "-out", directory / f"{name}.pem")
        (directory / f"{name}.key").chmod(0o600)


async def echo(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        await close(writer)


async def agent(args):
    ipaddress.ip_address(args.address)
    suite = Suite(args)
    certs = suite.out / "certificates"
    await certificates(certs, args.address)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certs / "server.pem", certs / "server.key")
    context.load_verify_locations(certs / "ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    def traced_echo(kind):
        async def handle(reader, writer):
            started = time.time()
            received = 0
            prefix = bytearray()
            error = None
            try:
                while data := await reader.read(65536):
                    received += len(data)
                    prefix.extend(data[:max(0, 16 - len(prefix))])
                    writer.write(data)
                    await writer.drain()
            except OSError as exc:
                error = repr(exc)
            finally:
                with (suite.out / "echo-events.jsonl").open("a") as log:
                    log.write(json.dumps({"kind": kind, "started_at_unix": started, "finished_at_unix": time.time(),
                                          "synthetic_stream_id": prefix.hex(), "received_bytes": received, "error": error}) + "\n")
                await close(writer)
        return handle
    control = await asyncio.start_server(traced_echo("direct-mtls"), "0.0.0.0", args.port + 1, ssl=context, ssl_handshake_timeout=10)
    tcp = await asyncio.start_server(traced_echo("tunnel-target"), "127.0.0.1", 0)
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(EchoUDP, local_addr=("127.0.0.1", 0))
    tcp_port = tcp.sockets[0].getsockname()[1]
    udp_port = udp.get_extra_info("sockname")[1]
    reverse_port, mgmt = port(), port()
    policy = suite.out / "restrictions.yaml"
    policy.write_text(f"""restrictions:
  - name: Disposable WAN qualification
    match:
      - !PathPrefix '^v1$'
    allow:
      - !Tunnel
        protocol: [Tcp, Udp]
        port: [{tcp_port}, {udp_port}]
        host: '^127\\.0\\.0\\.1$'
        cidr: [127.0.0.1/32]
      - !ReverseTunnel
        protocol: [Tcp]
        port: [{reverse_port}]
        cidr: [127.0.0.1/32]
""")
    server = None
    sampler = None
    try:
        server = await suite.spawn("wan-server", "server", f"wts://0.0.0.0:{args.port}",
                                   "--tls-certificate", str(certs / "server.pem"), "--tls-private-key", str(certs / "server.key"),
                                   "--tls-client-ca-certs", str(certs / "ca.pem"), "--restrict-config", str(policy),
                                   "--management-api", f"127.0.0.1:{mgmt}", "--remote-to-local-server-idle-timeout", "3s", log_level="INFO")
        await suite.ready(args.port, server)
        manifest = {"address": args.address, "port": args.port, "tcp_target": tcp_port, "udp_target": udp_port,
                    "tls_control_port": args.port + 1,
                    "reverse_port": reverse_port, "pid": server.pid, "management_port": mgmt,
                    "binary_sha256": hashlib.sha256(suite.binary.read_bytes()).hexdigest(),
                    "started_at_unix": time.time(), "expires_at_unix": time.time() + args.seconds,
                    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "expires_after_seconds": args.seconds, "identity": "disposable mTLS only"}
        (suite.out / "agent.json").write_text(json.dumps(manifest, indent=2))
        async def sample():
            group = next(line.split("::", 1)[1] for line in Path("/proc/self/cgroup").read_text().splitlines() if "::" in line)
            cpu_stat = Path("/sys/fs/cgroup") / group.lstrip("/") / "cpu.stat"
            while True:
                row = {"at_unix": time.time()}
                try:
                    row["cpu_stat"] = cpu_stat.read_text()
                    row["sockets"] = (await command("ss", "-tin", f"( sport = :{args.port} or sport = :{args.port + 1} )", timeout=3)).decode()
                except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
                    row["diagnostic_error"] = repr(exc)
                with (suite.out / "socket-samples.jsonl").open("a") as log:
                    log.write(json.dumps(row) + "\n")
                await asyncio.sleep(1)
        sampler = asyncio.create_task(sample())
        stopped = asyncio.Event()
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stopped.set)
        try:
            await asyncio.wait_for(stopped.wait(), args.seconds)
        except asyncio.TimeoutError:
            pass
    finally:
        if sampler:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
        if server:
            await suite.stop(server)
        tcp.close()
        await tcp.wait_closed()
        control.close()
        await control.wait_closed()
        udp.close()


async def probe(endpoint, timeout=20, output=None):
    writer = None
    started = time.monotonic()
    row = {"started_at_unix": time.time(), "port": endpoint, "timeout_seconds": timeout, "stage": "connect"}
    async def exchange():
        nonlocal writer
        reader, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        row["stage"] = "write"
        data = b"verified-native-reverse-wan"
        writer.write(data)
        await writer.drain()
        row["stage"] = "read"
        assert await reader.readexactly(len(data)) == data
        row["stage"] = "complete"
    try:
        await asyncio.wait_for(exchange(), timeout)
    except BaseException as exc:
        row["error"] = type(exc).__name__
        raise
    finally:
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if writer:
            await close(writer)
        if output:
            with (Path(output) / "probe-events.jsonl").open("a") as log:
                log.write(json.dumps(row) + "\n")


async def client(args):
    suite = Suite(args)
    async def ssh(*argv):
        return await command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.remote,
                             shlex.join(map(str, argv)), timeout=args.exchange_timeout + 10)
    manifest = json.loads(await ssh("cat", f"{args.directory}/agent.json"))
    certs = suite.out / "certificates"
    certs.mkdir(mode=0o700)
    archive = await ssh("tar", "-C", f"{args.directory}/certificates", "-cf", "-", "ca.pem", "client.pem", "client.key")
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        for name in ("ca.pem", "client.pem", "client.key"):
            (certs / name).write_bytes(files.extractfile(name).read())
            (certs / name).chmod(0o600)
    (suite.out / "metadata.json").write_text(json.dumps({"started_at": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        "remote": args.remote, "agent": manifest,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "binary_sha256": hashlib.sha256(suite.binary.read_bytes()).hexdigest(),
        "limits": "16 concurrent connections; short bursts only; no firewall changes", "args": vars(args)}, indent=2))
    if manifest.get("expires_at_unix", time.time() + 1) <= time.time():
        raise RuntimeError("staging agent has expired")
    async def socket_samples():
        while True:
            row = {"at_unix": time.time()}
            try:
                row["sockets"] = (await command("ss", "-tin", f"( dport = :{manifest['port']} or dport = :{manifest['tls_control_port']} )", timeout=3)).decode()
            except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
                row["diagnostic_error"] = repr(exc)
            with (suite.out / "client-socket-samples.jsonl").open("a") as log:
                log.write(json.dumps(row) + "\n")
            await asyncio.sleep(1)
    sampler = asyncio.create_task(socket_samples())
    suite.echo_port = manifest["tcp_target"]
    local_echo = await asyncio.start_server(echo, "127.0.0.1", 0)
    async def traced_batch(mode, endpoint, count):
        async def exchange():
            stream_id = uuid.uuid4().bytes
            row = {"stream_id": stream_id.hex(), "mode": mode, "started_at_unix": time.time(), "received_bytes": 0}
            writer = None
            start = time.monotonic()
            try:
                row["stage"] = "local-connect-or-proxy-negotiation"
                reader, writer = await suite.connect(mode, endpoint)
                row["local_connect_or_proxy_ms"] = round((time.monotonic() - start) * 1000, 3)
                data = stream_id + os.urandom(16384 - len(stream_id))
                for i in range(2):
                    row["stage"] = f"write-{i}"
                    writer.write(data)
                    await writer.drain()
                    row["stage"] = f"read-{i}"
                    try:
                        response = await reader.readexactly(len(data))
                    except asyncio.IncompleteReadError as exc:
                        row["received_bytes"] += len(exc.partial)
                        raise
                    row["received_bytes"] += len(response)
                    assert response == data
                row["stage"] = "complete"
                return (time.monotonic() - start) * 1000
            except BaseException as exc:
                row["error"] = type(exc).__name__
                raise
            finally:
                row["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
                with (suite.out / "exchanges.jsonl").open("a") as log:
                    log.write(json.dumps(row) + "\n")
                if writer:
                    suite.owned_writers.discard(writer)
                    await close(writer)
        started = time.monotonic()
        outcomes = await asyncio.gather(*(asyncio.wait_for(exchange(), args.exchange_timeout) for _ in range(count)), return_exceptions=True)
        errors = [f"{type(x).__name__}: {x}" for x in outcomes if isinstance(x, BaseException)]
        details = {"connections": count, "successful": count - len(errors), "errors": errors,
                   "pool_timeout_seconds": args.pool_timeout, "exchange_timeout_seconds": args.exchange_timeout,
                   "duration_seconds": round(time.monotonic() - started, 3)}
        assert not errors, json.dumps(details)
        return details
    try:
        if "tls_control_port" in manifest:
            context = ssl.create_default_context(cafile=certs / "ca.pem")
            context.load_cert_chain(certs / "client.pem", certs / "client.key")
            async def control(n):
                async def exchange():
                    start = time.monotonic()
                    r, w = await asyncio.open_connection(manifest["address"], manifest["tls_control_port"], ssl=context)
                    try:
                        for _ in range(2):
                            data = b"c" * 16384
                            w.write(data)
                            await w.drain()
                            assert await r.readexactly(len(data)) == data
                        return (time.monotonic() - start) * 1000
                    finally:
                        await close(w)
                timings = sorted(await asyncio.gather(*(asyncio.wait_for(exchange(), args.exchange_timeout) for _ in range(n))))
                return {"connections": n, "payload_bytes_per_connection": 32768, "min_ms": round(timings[0], 3),
                        "max_ms": round(timings[-1], 3), "timeout_seconds": args.exchange_timeout}
            for n in ((16,) if args.investigate else (1, 4, 16)):
                await suite.check(f"wan/control/direct-mtls-{n}", lambda count=n: control(count), args.exchange_timeout + 5)
        for scheme in (("wss", "https") if args.investigate else ("wss", "https", "wts")):
            ep = {name: port() for name in ("tcp", "socks", "http", "udp")}
            unix = str(suite.out / f"{scheme}.sock")
            options = ["-L", f"tcp://127.0.0.1:{ep['tcp']}:127.0.0.1:{suite.echo_port}",
                       "-L", f"socks5://127.0.0.1:{ep['socks']}", "-L", f"http://127.0.0.1:{ep['http']}",
                       "-L", f"udp://127.0.0.1:{ep['udp']}:127.0.0.1:{manifest['udp_target']}",
                       "-L", f"unix://{unix}:127.0.0.1:{suite.echo_port}",
                       "-R", f"tcp://127.0.0.1:{manifest['reverse_port']}:127.0.0.1:{local_echo.sockets[0].getsockname()[1]}"]
            process = await suite.spawn(f"wan-{scheme}", "client", *options, "--connection-retry-max-backoff", f"{args.pool_timeout}s",
                                        "--tls-verify-certificate", "--tls-certificate", str(certs / "client.pem"),
                                        "--tls-private-key", str(certs / "client.key"),
                                        f"{scheme}://{manifest['address']}:{manifest['port']}",
                                        extra_env={"SSL_CERT_FILE": str(certs / "ca.pem"), "SSL_CERT_DIR": ""}, log_level=args.client_log_level)
            try:
                await suite.ready(ep["tcp"], process)
                if args.investigate:
                    mode = "socks" if scheme == "wss" else "tcp"
                    for repeat in range(args.repeats):
                        await suite.check(f"investigate/{scheme}/{mode}/repeat-{repeat}",
                                          lambda m=mode: traced_batch(m, ep[m], 16), args.exchange_timeout + 5)
                    continue
                for mode in ("tcp", "socks", "http", "unix"):
                    for n in ((1, 4, 16) if mode == "tcp" else (16,)):
                        await suite.check(f"wan/{scheme}/{mode}/concurrent-{n}",
                                          lambda m=mode, count=n: traced_batch(m, unix if m == "unix" else ep[m], count), args.exchange_timeout + 5)
                for size in (1200, 40000):
                    await suite.check(f"wan/{scheme}/udp-{size}", lambda n=size: suite.udp(ep["udp"], n, 8), 15)
                async def reverse():
                    await asyncio.sleep(1)
                    await ssh("python3", args.agent_script, "--probe", str(manifest["reverse_port"]),
                              "--exchange-timeout", str(args.exchange_timeout), "--output", args.directory)
                    return {"verified_native_reverse_wan": True, "remote_trigger": "SSH; not a reverse RTT measurement",
                            "probe_timeout_seconds": args.exchange_timeout}
                await suite.check(f"wan/{scheme}/reverse-tcp", reverse, args.exchange_timeout + 5)
            finally:
                await suite.stop(process)
                await asyncio.sleep(4)
    finally:
        sampler.cancel()
        await asyncio.gather(sampler, return_exceptions=True)
        local_echo.close()
        await local_echo.wait_closed()
        for writer in suite.owned_writers.copy():
            await close(writer)
        await asyncio.gather(*(suite.stop(p) for p in suite.processes))
    return any(row["status"] == "fail" for row in suite.results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", action="store_true")
    parser.add_argument("--probe", type=int)
    parser.add_argument("--binary", default="target/release/tunward")
    parser.add_argument("--output", required=False)
    parser.add_argument("--address")
    parser.add_argument("--port", type=int, default=44443)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--long-run", action="store_true", help="explicitly permit an expiring agent lasting up to 72 hours plus cleanup margin")
    parser.add_argument("--client-log-level", choices=("INFO", "DEBUG"), default="INFO")
    parser.add_argument("--remote")
    parser.add_argument("--directory")
    parser.add_argument("--agent-script")
    parser.add_argument("--exchange-timeout", type=int, default=20)
    parser.add_argument("--pool-timeout", type=int, default=3)
    parser.add_argument("--investigate", action="store_true")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not (1 <= args.exchange_timeout <= 60 and 1024 <= args.port <= 65534):
        parser.error("exchange timeout 1..60 seconds and port 1024..65534")
    if not (1 <= args.pool_timeout <= 60 and 1 <= args.repeats <= 5):
        parser.error("pool timeout 1..60 seconds and repeats 1..5")
    if args.probe:
        asyncio.run(probe(args.probe, args.exchange_timeout, args.output))
    elif args.agent:
        if not args.address or not args.output or not 1 <= args.seconds <= (262800 if args.long_run else 900):
            parser.error("agent needs address/output; duration 1..900 seconds, or up to 262800 with --long-run")
        asyncio.run(agent(args))
    else:
        if not all((args.remote, args.directory, args.agent_script, args.output)):
            parser.error("client needs remote/directory/agent-script/output")
        raise SystemExit(bool(asyncio.run(client(args))))


if __name__ == "__main__":
    main()
