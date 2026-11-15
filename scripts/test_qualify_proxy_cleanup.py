import asyncio
import sys
import unittest

from qualify import close
from qualify_proxy_cleanup import open_application, reset


@unittest.skipUnless(sys.platform.startswith("linux"), "the cleanup runner uses Linux socket/proc semantics")
class CleanupHelperTests(unittest.IsolatedAsyncioTestCase):
    async def server(self, handler):
        tasks = set()
        async def accept(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            try:
                await handler(reader, writer)
            finally:
                await close(writer)
                tasks.discard(task)
        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        async def cleanup():
            server.close()
            for task in tuple(tasks):
                task.cancel()
            await asyncio.gather(*tuple(tasks), return_exceptions=True)
            await server.wait_closed()
        self.addAsyncCleanup(cleanup)
        return server.sockets[0].getsockname()[1]

    async def test_reset_is_observed_as_reset_instead_of_directional_eof(self):
        received, outcome = asyncio.Event(), asyncio.get_running_loop().create_future()
        async def peer(reader, writer):
            self.assertEqual(await reader.readexactly(1), b"x")
            received.set()
            try:
                data = await reader.read(1)
                outcome.set_result(("eof", data))
            except ConnectionResetError:
                outcome.set_result(("reset", None))
        endpoint = await self.server(peer)
        _, writer = await asyncio.open_connection("127.0.0.1", endpoint)
        writer.write(b"x")
        await writer.drain()
        await asyncio.wait_for(received.wait(), 2)
        reset(writer)
        self.assertEqual(await asyncio.wait_for(outcome, 2), ("reset", None))
        await close(writer)

    async def test_http_proxy_denial_is_not_an_established_tunnel(self):
        async def deny(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        endpoint = await self.server(deny)
        with self.assertRaises(AssertionError):
            await asyncio.wait_for(open_application("forward-http", endpoint, 80), 2)

    async def test_socks_denial_is_not_an_established_tunnel(self):
        async def deny(reader, writer):
            self.assertEqual(await reader.readexactly(3), b"\x05\x01\x00")
            writer.write(b"\x05\x00")
            await writer.drain()
            await reader.readexactly(10)
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
        endpoint = await self.server(deny)
        with self.assertRaises(AssertionError):
            await asyncio.wait_for(open_application("reverse-socks", endpoint, 80), 2)


if __name__ == "__main__":
    unittest.main()
