import asyncio
import socket
import unittest

from qualify import close
from qualify_recovery import Relay


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tasks = set()
        async def echo(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            except OSError:
                pass
            finally:
                await close(writer)
                self.tasks.discard(task)
        self.target = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.address = self.target.sockets[0].getsockname()
        self.relay, self.port = await Relay.open(self.address)
        self.addAsyncCleanup(self.relay.shutdown)

    async def asyncTearDown(self):
        await self.relay.shutdown()
        self.target.close()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        await self.target.wait_closed()

    async def test_shutdown_closes_active_tcp_before_waiting_for_listener(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"ready")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2), b"ready")
            await asyncio.wait_for(self.relay.shutdown(), 2)
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        finally:
            await close(writer)

    async def test_tcp_outage_drops_existing_path_and_recovers_after_restore(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"before")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 2), b"before")
            self.relay.cut()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        finally:
            await close(writer)
        self.relay.online = True
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"after")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2), b"after")
        finally:
            await close(writer)

    async def test_udp_outage_drops_both_directions_and_restores(self):
        loop = asyncio.get_running_loop()
        # The relay distinguishes replies by the target address, not by packet contents.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as client:
            target.bind(("127.0.0.1", 0))
            self.relay.target = target.getsockname()
            client.bind(("127.0.0.1", 0))
            target.setblocking(False)
            client.setblocking(False)
            destination = ("127.0.0.1", self.port)
            await loop.sock_sendto(client, b"before", destination)
            data, address = await asyncio.wait_for(loop.sock_recvfrom(target, 1024), 2)
            self.assertEqual(data, b"before")
            await loop.sock_sendto(target, data, address)
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(client, 1024), 2), b"before")
            self.relay.cut()
            await loop.sock_sendto(client, b"dropped", destination)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(loop.sock_recv(target, 1024), .05)
            await loop.sock_sendto(target, b"dropped-reply", address)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(loop.sock_recv(client, 1024), .05)
            self.relay.online = True
            await loop.sock_sendto(client, b"after", destination)
            data, _ = await asyncio.wait_for(loop.sock_recvfrom(target, 1024), 2)
            self.assertEqual(data, b"after")


if __name__ == "__main__":
    unittest.main()
