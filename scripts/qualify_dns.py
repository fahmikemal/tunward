#!/usr/bin/env python3
"""Controlled UDP DNS, DoT, DoH, address fallback, and ECH edge cases on loopback."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct

from qualify_runtime import RuntimeChecks, close, port


class DNSChecks(RuntimeChecks):
    def response(self, query):
        offset, labels = 12, []
        while query[offset]:
            length = query[offset]
            labels.append(query[offset + 1:offset + length + 1].decode())
            offset += length + 1
        offset += 1
        kind, cls = struct.unpack("!HH", query[offset:offset + 4])
        name = ".".join(labels).lower()
        self.queries.append({"name": name, "type": kind})
        payload = None
        if name != "missing.test":
            if kind == 1:
                payload = socket.inet_aton("127.0.0.1")
            elif kind == 28 and name == "dual.test":
                payload = socket.inet_pton(socket.AF_INET6, "::1")
            elif kind == 65 and name == "invalid-ech.test":
                payload = b"\x00\x01\x00" + struct.pack("!HH", 5, 2) + b"\x00\x00"
        answer = b"" if payload is None else b"\xc0\x0c" + struct.pack("!HHIH", kind, cls, 0, len(payload)) + payload
        header = query[:2] + struct.pack("!HHHHH", 0x8183 if name == "missing.test" else 0x8180, 1, int(payload is not None), 0, 0)
        return header + query[12:offset + 4] + answer

    async def run(self):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import DataReceived, RequestReceived, StreamEnded

        await self.prepare()
        self.queries = []
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                await close(writer)
        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        owner = self
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, peer):
                self.transport.sendto(owner.response(data), peer)
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=("127.0.0.1", 0))
        async def dot(reader, writer):
            try:
                while True:
                    length = struct.unpack("!H", await reader.readexactly(2))[0]
                    answer = self.response(await reader.readexactly(length))
                    writer.write(struct.pack("!H", len(answer)) + answer)
                    await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                await close(writer)
        async def doh(reader, writer):
            connection = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
            connection.initiate_connection()
            writer.write(connection.data_to_send())
            bodies = {}
            try:
                while data := await reader.read(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, RequestReceived):
                            bodies[event.stream_id] = bytearray()
                        elif isinstance(event, DataReceived):
                            bodies[event.stream_id].extend(event.data)
                            connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, StreamEnded):
                            answer = self.response(bytes(bodies.pop(event.stream_id)))
                            connection.send_headers(event.stream_id, [(":status", "200"), ("content-type", "application/dns-message")])
                            connection.send_data(event.stream_id, answer, end_stream=True)
                    writer.write(connection.data_to_send())
                    await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                await close(writer)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.certs / "server.pem", self.certs / "server.key")
        dot_server = await asyncio.start_server(dot, "127.0.0.1", 0, ssl=tls)
        doh_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        doh_tls.load_cert_chain(self.certs / "server.pem", self.certs / "server.key")
        doh_tls.set_alpn_protocols(["h2"])
        doh_server = await asyncio.start_server(doh, "127.0.0.1", 0, ssl=doh_tls)
        resolvers = {"udp": f"dns://127.0.0.1:{udp.get_extra_info('sockname')[1]}",
                     "dot": f"dns+tls://127.0.0.1:{dot_server.sockets[0].getsockname()[1]}?sni=localhost",
                     "doh": f"dns+https://127.0.0.1:{doh_server.sockets[0].getsockname()[1]}?sni=localhost"}
        try:
            server_port = port()
            server = await self.spawn("server", "server", "--tls-certificate", self.certs / "server.pem",
                "--tls-private-key", self.certs / "server.key", "--tls-client-ca-certs", self.certs / "ca.pem",
                "--restrict-to", f"127.0.0.1:{target_port}", f"wts://127.0.0.1:{server_port}")
            await self.ready(server_port, server)
            async def case(name, resolver, scheme, hostname="v4.test", allowed=True, ech=False, startup_denied=False):
                endpoint = port()
                before = len(self.queries)
                client = await self.spawn(name.replace("/", "-"), "client", "--tls-verify-certificate",
                    "--tls-certificate", self.certs / "client.pem", "--tls-private-key", self.certs / "client.key",
                    "--tls-sni-override", "localhost", "--dns-resolver", resolver,
                    "--connection-retry-max-backoff", "1s", *( ["--tls-ech-enable"] if ech else []),
                    "-L", f"tcp://127.0.0.1:{endpoint}:127.0.0.1:{target_port}", f"{scheme}://{hostname}:{server_port}")
                try:
                    if startup_denied:
                        assert await asyncio.wait_for(client.wait(), 5) != 0
                    else:
                        await self.ready(endpoint, client)
                        if allowed:
                            await self.exchange(endpoint)
                        else:
                            try:
                                await self.exchange(endpoint)
                            except (OSError, asyncio.IncompleteReadError):
                                pass
                            else:
                                raise AssertionError("forbidden DNS/TLS case delivered traffic")
                    if "wrong.invalid" not in resolver and not (scheme == "wts" and ech):
                        assert len(self.queries) > before, "test did not use controlled resolver"
                    self.record(name, allowed=allowed, ech_encrypted=False if ech else None)
                except Exception as exc:
                    self.record(name, "fail", error=f"{type(exc).__name__}: {exc}")
                finally:
                    if client.returncode is None:
                        client.terminate()
                        await client.wait()
            for resolver_name, resolver in resolvers.items():
                for scheme in ("wss", "https", "wts"):
                    for hostname in ("v4.test", "dual.test", "missing.test"):
                        await case(f"dns/{resolver_name}/{scheme}/{hostname}", resolver, scheme, hostname, hostname != "missing.test")
            for resolver_name in ("dot", "doh"):
                await case(f"dns/{resolver_name}/wrong-resolver-name", resolvers[resolver_name].replace("localhost", "wrong.invalid"), "wss", allowed=False)
            for scheme in ("wss", "https"):
                await case(f"ech/{scheme}/invalid-config-opportunistic-fallback", resolvers["doh"], scheme, "invalid-ech.test", ech=True)
                await case(f"ech/{scheme}/missing-https-record-denied", resolvers["doh"], scheme, "v4.test", allowed=False, ech=True, startup_denied=True)
            await case("ech/wts/unsupported-option-denied", resolvers["doh"], "wts", allowed=False, ech=True, startup_denied=True)
        finally:
            for process in self.processes:
                if process.returncode is None:
                    process.terminate()
                    await process.wait()
            for service in (target, dot_server, doh_server):
                service.close()
                await service.wait_closed()
            udp.close()
            (self.out / "queries.json").write_text(json.dumps(self.queries, indent=2) + "\n")
            (self.out / "metadata.json").write_text(json.dumps({"binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "controlled loopback UDP DNS/DoT/DoH; AAAA failure with IPv4 fallback; ECH malformed/absent records and WT rejection; no successful ECH encryption or real CDN"}, indent=2) + "\n")
        return any(r["status"] == "fail" for r in self.results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/tunward"))
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(bool(asyncio.run(DNSChecks(parser.parse_args()).run())))
