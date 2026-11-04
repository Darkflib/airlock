import asyncio
import socket
import struct

from airlock.dnsguard import DnsGuard, qname


def query(name: str, qid: int = 0x1234) -> bytes:
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return q + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)


class FakeUpstream(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(data[:2] + b"UPSTREAM", addr)


async def ask(port: int, packet: bytes) -> bytes | None:
    loop = asyncio.get_running_loop()

    def go():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(packet, ("127.0.0.1", port))
            try:
                return s.recv(4096)
            except socket.timeout:
                return None
    return await loop.run_in_executor(None, go)


def test_registry_names_are_forwarded_everything_else_refused_and_recorded():
    async def main():
        loop = asyncio.get_running_loop()
        up_t, _ = await loop.create_datagram_endpoint(FakeUpstream, local_addr=("127.0.0.1", 0))
        guard = DnsGuard(("registry.npmjs.org",), upstream=up_t.get_extra_info("sockname"))
        port = await guard.start()
        try:
            assert (await ask(port, query("registry.npmjs.org")))[2:] == b"UPSTREAM"
            nx = await ask(port, query("aGVsbG8.exfil.example.com", qid=0xBEEF))
            assert nx[:2] == b"\xbe\xef" and nx[3] & 0xF == 3            # NXDOMAIN for the same query id
            assert qname(nx) == "aGVsbG8.exfil.example.com"
            assert await ask(port, b"\x00\x01junk") is None             # malformed: dropped, but recorded
            assert [r["name"] for r in guard.drain()] == ["aGVsbG8.exfil.example.com", "(malformed query)"]
            assert guard.drain() == []
        finally:
            guard.close()
            up_t.close()
    asyncio.run(main())
