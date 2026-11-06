"""Outside catcher: a box that is not the Airlock host, listening for anything a sandbox gets out.

Writes one JSON line per contact to /var/lib/catcher/hits.jsonl:
- TCP on 80, 443, 4444, 8080, 47801 and 53: the first bytes sent (an HTTP request is answered "ok",
  a TLS hello is kept as is, so its SNI shows), dual stack.
- DNS on UDP and TCP 53, authoritative for ZONE: every query name is logged, names in the zone get
  this box's address. A token in a lookup that reached any real resolver on the internet ends up here.
- ICMP echo requests (IPv4), with their payload.
Standard library only; runs as root (port 53, raw ICMP). Internet scanners hit it too: the lab
report counts only contacts carrying a run's token or coming from the Airlock host.
"""

import asyncio
import json
import os
import socket
import struct
import time

ZONE = os.environ.get("CATCHER_ZONE", "catch.darkflib.dev").lower().rstrip(".")
LOG = os.environ.get("CATCHER_LOG", "/var/lib/catcher/hits.jsonl")
TCP_PORTS = (80, 443, 4444, 8080, 47801, 53)


def own(family: int, probe: str) -> str | None:
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((probe, 53))
            return s.getsockname()[0]
    except OSError:
        return None


V4, V6 = own(socket.AF_INET, "8.8.8.8"), own(socket.AF_INET6, "2001:4860:4860::8888")


def log(kind: str, peer: str, **data) -> None:
    with open(LOG, "a") as f:
        f.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "t": time.time(),
                            "kind": kind, "peer": peer, **data}) + "\n")


def peer_ip(addr) -> str:
    ip = addr[0]
    return ip[7:] if ip.startswith("::ffff:") else ip


def dns_answer(q: bytes) -> tuple[str, int, bytes | None]:
    """(name, qtype, reply) for one DNS query; reply is None when it can't be parsed."""
    try:
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace"))
            i += 1 + q[i]
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0]
        question = q[12:i + 5]
    except (IndexError, struct.error):
        return "", 0, None
    name = ".".join(labels)
    lower = name.lower()
    in_zone = lower == ZONE or lower.endswith("." + ZONE)
    rdata = None
    if in_zone and qtype == 1 and V4:
        rdata = socket.inet_pton(socket.AF_INET, V4)
    elif in_zone and qtype == 28 and V6:
        rdata = socket.inet_pton(socket.AF_INET6, V6)
    flags = 0x8400 | (0 if in_zone else 3)  # authoritative; NXDOMAIN outside the zone
    head = q[:2] + struct.pack("!HHHHH", flags, 1, 1 if rdata else 0, 0, 0)
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata) if rdata else b""
    return name, qtype, head + question + answer


class Udp53(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        name, qtype, reply = dns_answer(data)
        log("dns", peer_ip(addr), proto="udp", name=name, qtype=qtype)
        if reply:
            self.transport.sendto(reply, addr)


async def on_tcp(reader, writer):
    port = writer.get_extra_info("sockname")[1]
    peer = peer_ip(writer.get_extra_info("peername"))
    data = b""
    try:
        data = await asyncio.wait_for(reader.read(8192), 3)
        if port == 53 and len(data) > 2:
            name, qtype, reply = dns_answer(data[2:])
            log("dns", peer, proto="tcp", name=name, qtype=qtype)
            if reply:
                writer.write(struct.pack("!H", len(reply)) + reply)
        else:
            log("tcp", peer, port=port, bytes=len(data), data=data[:2000].decode("latin-1"))
            if data[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD"):
                writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n")
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        if not data:
            log("tcp", peer, port=port, bytes=0, data="")
    finally:
        writer.close()


def icmp_reader(loop) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setblocking(False)

    def ready():
        try:
            pkt, addr = s.recvfrom(65535)
        except OSError:
            return
        ihl = (pkt[0] & 15) * 4
        if len(pkt) > ihl and pkt[ihl] == 8:  # echo request
            log("icmp", addr[0], bytes=len(pkt) - ihl - 8, data=pkt[ihl + 8:ihl + 72].hex())
    loop.add_reader(s, ready)


async def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    loop = asyncio.get_running_loop()
    servers = [await asyncio.start_server(on_tcp, host=None, port=p) for p in TCP_PORTS]  # every address, v4 and v6
    for fam, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)  # else it claims v4 port 53 too
        s.bind((host, 53))
        await loop.create_datagram_endpoint(Udp53, sock=s)
    icmp_reader(loop)
    log("start", "", zone=ZONE, v4=V4, v6=V6)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
