import json
from pathlib import Path
import shutil
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import qualify_runtime
from qualify_runtime import RuntimeChecks, port, udp_exchange


class PortTests(unittest.TestCase):
    def test_port_skips_candidates_whose_udp_side_is_taken(self):
        # Hold the UDP side of the first candidate the OS will hand out, as another process might.
        real_socket = socket.socket
        taken = []

        class FirstUdpBusy(real_socket):
            def bind(self, address):
                if self.type == socket.SOCK_DGRAM and not taken:
                    taken.append(address[1])
                    raise OSError(98, "Address already in use")
                return super().bind(address)

        with patch.object(qualify_runtime.socket, "socket", FirstUdpBusy):
            endpoint = port()
        self.assertEqual(len(taken), 1)
        self.assertNotEqual(endpoint, taken[0])
        with real_socket() as stream, real_socket(type=socket.SOCK_DGRAM) as datagram:
            stream.bind(("127.0.0.1", endpoint))
            datagram.bind(("127.0.0.1", endpoint))

    def test_port_is_not_handed_out_twice(self):
        endpoints = [port() for _ in range(20)]
        self.assertEqual(len(endpoints), len(set(endpoints)))


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required")
class RuntimeCertificateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary = self.root / "binary"
        binary.write_bytes(b"unused by certificate preparation")
        self.checks = RuntimeChecks(SimpleNamespace(binary=binary, output=self.root / "evidence"))

    async def test_certificate_generation_ignores_ambient_extensions(self):
        config = self.root / "ambient.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=conflicting_ca\n"
                          "req_extensions=conflicting_ca\n[dn]\nCN=Ambient CA\n"
                          "[conflicting_ca]\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,keyEncipherment\n")
        with patch.dict("os.environ", {"OPENSSL_CONF": str(config)}):
            await self.checks.prepare()
        ca = (await self.checks.command("openssl", "x509", "-in", self.checks.certs / "ca.pem",
                                       "-text", "-noout")).decode()
        self.assertEqual(ca.count("X509v3 Basic Constraints:"), 1)
        self.assertEqual(ca.count("X509v3 Key Usage:"), 1)
        self.assertIn("CA:TRUE", ca)
        self.assertTrue(self.checks.openssl_version)

    async def test_setup_failure_preserves_evidence(self):
        async def fail(*_args):
            raise RuntimeError("OpenSSL fixture failure")
        with patch.object(self.checks, "command", side_effect=fail):
            self.assertTrue(await self.checks.run())
        results = json.loads((self.checks.out / "results.json").read_text())
        self.assertEqual(results[0]["name"], "runtime/setup")
        self.assertEqual(results[0]["status"], "fail")
        self.assertIn("OpenSSL fixture failure", results[0]["error"])
        metadata = json.loads((self.checks.out / "metadata.json").read_text())
        self.assertIn("binary_sha256", metadata)


class RuntimeDatagramTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_size_limit_still_exercises_udp(self):
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, peer):
                self.transport.sendto(data, peer)

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        self.addCleanup(transport.close)
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            sock.connect(transport.get_extra_info("sockname"))
            send = loop.sock_sendall
            attempts = 0

            async def reject_large_once(stream, data):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError(errno.EMSGSIZE, "controlled host size limit")
                return await send(stream, data)

            with patch.object(loop, "sock_sendall", side_effect=reject_large_once):
                self.assertEqual(await udp_exchange(sock), 8192)
            self.assertEqual(attempts, 2)

    async def test_other_send_errors_are_not_hidden(self):
        loop = asyncio.get_running_loop()
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            with patch.object(loop, "sock_sendall", side_effect=OSError(errno.ENETUNREACH, "fixture unreachable")):
                with self.assertRaises(OSError) as raised:
                    await udp_exchange(sock)
        self.assertEqual(raised.exception.errno, errno.ENETUNREACH)


if __name__ == "__main__":
    unittest.main()
import asyncio
import errno
