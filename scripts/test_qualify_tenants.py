import asyncio
import socket
import unittest

from qualify_tenants import TenantChecks


class Echo(asyncio.DatagramProtocol):
    """Echoes datagrams, except the copies `lost` says to drop, numbered from 0."""

    def __init__(self, lost=()):
        self.lost = set(lost)
        self.received = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        number = self.received
        self.received += 1
        if number not in self.lost:
            self.transport.sendto(data, addr)


class UdpPeerTests(unittest.IsolatedAsyncioTestCase):
    async def peer(self, echo, sends=5):
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: echo, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        self.addCleanup(transport.close)
        return await TenantChecks.udp_peer(transport.get_extra_info("sockname")[1], 0, wait=0.05, sends=sends)

    async def test_nothing_is_resent_when_every_echo_returns(self):
        echo = Echo()
        self.assertEqual(await self.peer(echo), 0)
        self.assertEqual(echo.received, 4)

    async def test_a_lost_datagram_is_sent_again_and_counted(self):
        echo = Echo(lost=[0, 3])
        self.assertEqual(await self.peer(echo), 2)
        self.assertEqual(echo.received, 6)

    async def test_a_listener_that_stays_silent_still_fails(self):
        echo = Echo(lost=range(100))
        with self.assertRaisesRegex(AssertionError, "datagram 0 was not echoed after 3 sends"):
            await self.peer(echo, sends=3)
        self.assertEqual(echo.received, 3)

    async def test_a_late_echo_of_an_earlier_copy_is_not_taken_for_the_next_datagram(self):
        class Late(Echo):
            """Holds the first echo past the first wait, so it arrives beside the second."""

            def datagram_received(self, data, addr):
                number = self.received
                self.received += 1
                delay = 0.07 if number == 0 else 0
                asyncio.get_running_loop().call_later(delay, self.transport.sendto, data, addr)

        echo = Late()
        self.assertEqual(await self.peer(echo), 1)
        self.assertEqual(echo.received, 5)


if __name__ == "__main__":
    unittest.main()
