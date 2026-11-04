"""Host-side DNS for one run, closing the DNS-label exfiltration path.

microsandbox's gateway resolver (the guest's original nameserver) recursively resolves any name,
so a package that queried it directly could smuggle data out in DNS labels past the sinkhole.
Each Workspace points the gateway at its own DnsGuard instead (Network.dns nameservers), on
127.0.0.1 with an ephemeral port, so every query is attributable to its run.

The guest's resolver is Airlock's watcher, which answers non-allowlisted names itself. So the
only non-allowlisted names that ever reach the gateway come from code bypassing the watcher:
they get NXDOMAIN and are recorded. Allowlisted registry names are forwarded to the host's
real resolver.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time


def host_resolver() -> str:
    try:
        for line in open("/etc/resolv.conf"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


def question_end(packet: bytes) -> int | None:
    """Offset just past the first question (name, type, class), or None if malformed."""
    i = 12
    while i < len(packet) and packet[i]:
        if packet[i] & 0xC0:  # compression pointers never appear in a query's question
            return None
        i += 1 + packet[i]
    return i + 5 if i + 5 <= len(packet) else None


def qname(packet: bytes) -> str | None:
    if question_end(packet) is None:
        return None
    labels, i = [], 12
    while packet[i]:
        labels.append(packet[i + 1:i + 1 + packet[i]].decode(errors="replace"))
        i += 1 + packet[i]
    return ".".join(labels)


def nxdomain(query: bytes) -> bytes:
    end = question_end(query)
    return query[:2] + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0) + query[12:end]


def allowlisted(name: str, allow: tuple[str, ...]) -> bool:
    name = name.lower().rstrip(".")
    return any(name == h or name.endswith("." + h) for h in allow)


class DnsGuard(asyncio.DatagramProtocol):
    def __init__(self, allow: tuple[str, ...], upstream: tuple[str, int] | None = None):
        self.allow = allow
        self.upstream = upstream or (host_resolver(), 53)
        self.blocked: list[dict] = []
        self.transport: asyncio.DatagramTransport | None = None

    async def start(self) -> int:
        """Listen on 127.0.0.1 and return the port for Network.dns."""
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: self, local_addr=("127.0.0.1", 0))
        return self.transport.get_extra_info("sockname")[1]

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        name = qname(data)
        if name is None:
            self.blocked.append({"name": "(malformed query)", "ts": time.time()})
            return
        if allowlisted(name, self.allow):
            asyncio.ensure_future(self._forward(data, addr))
            return
        self.blocked.append({"name": name, "ts": time.time()})
        self.transport.sendto(nxdomain(data), addr)

    async def _forward(self, data: bytes, addr) -> None:
        def ask() -> bytes | None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(4)
                try:
                    s.sendto(data, self.upstream)
                    return s.recv(4096)
                except OSError:
                    return None
        resp = await asyncio.get_running_loop().run_in_executor(None, ask)
        if resp and self.transport:
            self.transport.sendto(resp, addr)

    def drain(self) -> list[dict]:
        out, self.blocked = self.blocked, []
        return out

    def close(self) -> None:
        if self.transport:
            self.transport.close()
            self.transport = None
