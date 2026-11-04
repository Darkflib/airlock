"""Airlock in-guest watcher. Runs as root inside the microVM (stdlib only) while
the package is installed by an unprivileged user, and appends JSON lines to a
root-only log. Language-agnostic, unlike the Node tracer:

  * fanotify FAN_OPEN_EXEC on the root mount: every program executed, with pid
  * fanotify FAN_OPEN on home directories:     who opened which dotfile (canaries)
  * a DNS server on 127.0.0.1:53:              every name looked up, with pid. Allowlisted
                                               names are forwarded; with --sinkhole, every
                                               other name gets a fake address in the run's
                                               sinkhole /24 (Airlock's host proxy answers it)
  * /proc/net/tcp{,6} polling:                 outbound connections, with pid

  python3 watch.py <log.jsonl> <home> [<home> ...] [--sinkhole 198.18.N.0/24] [--allow a,b]
"""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time

_ap = argparse.ArgumentParser()
_ap.add_argument("log")
_ap.add_argument("homes", nargs="+")
_ap.add_argument("--sinkhole", help="per-run /24 for fake answers to non-allowlisted names")
_ap.add_argument("--allow", default="", help="comma-separated allowlisted hostnames")
ARGS = _ap.parse_args()
LOG_PATH, HOMES = ARGS.log, ARGS.homes
SINKHOLE = ipaddress.ip_network(ARGS.sinkhole) if ARGS.sinkhole else None
ALLOW = tuple(h.strip().lower() for h in ARGS.allow.split(",") if h.strip())
ME = os.getpid()
_lock = threading.Lock()
_log = open(LOG_PATH, "a", buffering=1)


def log(ev: str, **kw) -> None:
    with _lock:
        _log.write(json.dumps({"ts": time.time(), "ev": ev, **kw}) + "\n")


# --- process helpers -----------------------------------------------------------

def proc_info(pid: int) -> dict:
    info = {"pid": pid}
    try:
        info["cmd"] = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace").strip()[:300]
    except OSError:
        pass
    try:
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        status = open(f"/proc/{pid}/status").read()
        info["uid"] = int(re.search(r"^Uid:\s+(\d+)", status, re.M).group(1))
        info["ppid"] = int(re.search(r"^PPid:\s+(\d+)", status, re.M).group(1))
    except (OSError, AttributeError):
        pass
    return info


def is_self(pid: int) -> bool:
    return pid == ME


def pid_for_inode(inode: str) -> int | None:
    target = f"socket:[{inode}]"
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{d}/fd"):
                if os.readlink(f"/proc/{d}/fd/{fd}") == target:
                    return int(d)
        except OSError:
            continue
    return None


# --- fanotify ------------------------------------------------------------------

libc = ctypes.CDLL(None, use_errno=True)
FAN_CLASS_NOTIF, FAN_CLOEXEC = 0x0, 0x1
FAN_OPEN, FAN_OPEN_EXEC, FAN_EVENT_ON_CHILD = 0x20, 0x1000, 0x08000000
FAN_MARK_ADD, FAN_MARK_MOUNT = 0x1, 0x10
AT_FDCWD = -100
META = struct.Struct("IBBHQii")


def fanotify_loop() -> None:
    fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, os.O_RDONLY | os.O_LARGEFILE)
    if fd < 0:
        log("watch_error", what="fanotify_init", err=os.strerror(ctypes.get_errno()))
        return
    marks = [(FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC, "/")]
    for home in HOMES:
        for d in (home, f"{home}/.aws", f"{home}/.ssh", f"{home}/.config"):
            if os.path.isdir(d):
                marks.append((FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD, d))
    failed = 0
    for flags, mask, path in marks:
        if libc.fanotify_mark(fd, flags, ctypes.c_uint64(mask), AT_FDCWD, path.encode()) < 0:
            log("watch_error", what=f"fanotify_mark {path}", err=os.strerror(ctypes.get_errno()))
            failed += 1
    if failed:  # a missing mark means missed credential reads: never report ready
        return
    log("watch_ready", what="fanotify", marks=len(marks))
    while True:
        buf = os.read(fd, 65536)
        off = 0
        while off + META.size <= len(buf):
            ev_len, _, _, _, mask, efd, pid = META.unpack_from(buf, off)
            off += ev_len
            try:
                path = os.readlink(f"/proc/self/fd/{efd}") if efd >= 0 else "?"
            except OSError:
                path = "?"
            finally:
                if efd >= 0:
                    os.close(efd)
            if is_self(pid):
                continue
            if mask & FAN_OPEN_EXEC:
                if "/ld-linux" not in path:  # the dynamic loader is opened for every program
                    _execs.put((time.time(), pid, path, proc_info(pid).get("uid")))
            elif mask & FAN_OPEN and not os.path.isdir(path):
                log("open", path=path, **proc_info(pid))


# FAN_OPEN_EXEC fires when the binary is opened, before execve has replaced the
# process image, so /proc still shows the parent. Read it a moment later.
_execs: "queue.Queue[tuple[float, int, str, int | None]]" = queue.Queue()


def exec_loop() -> None:
    while True:
        ts, pid, path, uid_then = _execs.get()
        time.sleep(max(0.0, ts + 0.03 - time.time()))
        info = proc_info(pid)
        if info.get("exe") != path:  # exited already, or still the parent: keep only what we know
            info = {"pid": pid}
        info.setdefault("uid", uid_then)  # uid at event time; short-lived processes are gone by now
        log("exec", path=path, **info)


# --- DNS -----------------------------------------------------------------------

def upstream_resolver() -> str:
    for line in open("/etc/resolv.conf.airlock-orig"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            return parts[1]
    return "8.8.8.8"


def qname(packet: bytes) -> str:
    labels, i = [], 12
    while i < len(packet) and packet[i]:
        n = packet[i]
        labels.append(packet[i + 1:i + 1 + n].decode(errors="replace"))
        i += 1 + n
    return ".".join(labels)


def qtype(packet: bytes) -> int:
    i = 12
    while i < len(packet) and packet[i]:
        i += 1 + packet[i]
    return struct.unpack_from(">H", packet, i + 1)[0] if i + 3 <= len(packet) else 0


def allowlisted(name: str) -> bool:
    name = name.lower().rstrip(".")
    return any(name == h or name.endswith("." + h) for h in ALLOW)


def sinkhole_ip(name: str) -> str:
    """Stable fake address for a name inside the run's sinkhole /24 (.1 to .254)."""
    host = 1 + int(hashlib.sha256(name.lower().encode()).hexdigest(), 16) % 254
    return str(SINKHOLE.network_address + host)


def fake_answer(query: bytes, ip: str | None) -> bytes:
    """Answer the query ourselves: one A record, or an empty NOERROR (e.g. for AAAA,
    so clients fall back to IPv4 and reach the sinkhole)."""
    i = 12
    while query[i]:
        i += 1 + query[i]
    question = query[12:i + 5]
    header = query[:2] + struct.pack(">HHHHH", 0x8180, 1, 1 if ip else 0, 0, 0)
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)) if ip else b""
    return header + question + answer


def answer_ips(resp: bytes) -> list[str]:
    """A and AAAA records from a DNS response (enough parsing for our own forwarder)."""
    try:
        qd, an = struct.unpack_from(">HH", resp, 4)
        i = 12
        for _ in range(qd):
            while resp[i]:
                i += 1 + resp[i]
            i += 5
        ips = []
        for _ in range(an):
            if resp[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while resp[i]:
                    i += 1 + resp[i]
                i += 1
            rtype, _, _, rdlen = struct.unpack_from(">HHIH", resp, i)
            i += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, resp[i:i + 4]))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, resp[i:i + 16]))
            i += rdlen
        return ips
    except (struct.error, IndexError, ValueError):
        return []


def udp_pid(port: int) -> int | None:
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            for line in open(table).readlines()[1:]:
                f = line.split()
                if int(f[1].rsplit(":", 1)[1], 16) == port:
                    return pid_for_inode(f[9])
        except OSError:
            continue
    return None


def dns_loop() -> None:
    upstream = upstream_resolver()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 53))
    log("watch_ready", what="dns", upstream=upstream)
    while True:
        data, addr = srv.recvfrom(4096)
        pid = udp_pid(addr[1])
        info = proc_info(pid) if pid else {}
        name = qname(data)
        if SINKHOLE and name and not allowlisted(name):
            ip = sinkhole_ip(name)
            log("dns", name=name, sinkholed=ip, **info)
            srv.sendto(fake_answer(data, ip if qtype(data) == 1 else None), addr)
            log("dns_answer", name=name, ips=[ip], sinkholed=True)
            continue
        log("dns", name=name, **info)

        def forward(data=data, addr=addr):
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(5)
            try:
                up.sendto(data, (upstream, 53))
                resp = up.recv(4096)
                srv.sendto(resp, addr)
                ips = answer_ips(resp)
                if ips:
                    log("dns_answer", name=qname(data), ips=ips)
            except OSError:
                pass
            finally:
                up.close()
        threading.Thread(target=forward, daemon=True).start()


# --- SYN_SENT polling ------------------------------------------------------------

def hex_addr(h: str) -> str:
    ip, port = h.split(":")
    port = int(port, 16)
    raw = bytes.fromhex(ip)
    if len(raw) == 4:
        return f"{socket.inet_ntop(socket.AF_INET, raw[::-1])}:{port}"
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return f"[{socket.inet_ntop(socket.AF_INET6, words)}]:{port}"


TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0B": "CLOSING"}


def attempt_fails() -> int:
    try:
        rows = [line.split() for line in open("/proc/net/snmp") if line.startswith("Tcp:")]
        return int(rows[1][rows[0].index("AttemptFails")])
    except (OSError, ValueError, IndexError):
        return 0


def conn_loop() -> None:
    """Report every outbound TCP connection by a non-root user, in any state.
    The egress policy can accept a handshake before refusing, so SYN_SENT alone
    misses connections; /proc/net/tcp also records the owning uid."""
    seen: set[tuple[str, str]] = set()
    fails = attempt_fails()
    while True:
        # The egress policy answers some connects with an instant RST, gone before
        # any poll can see the socket. The kernel still counts them.
        now_fails = attempt_fails()
        if now_fails > fails:
            log("connect_refused", count=now_fails - fails)
            fails = now_fails
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                lines = open(table).readlines()[1:]
            except OSError:
                continue
            for line in lines:
                f = line.split()
                local, remote, state, uid, inode = f[1], f[2], f[3], int(f[7]), f[9]
                if state not in TCP_STATES or uid == 0 or (local, remote) in seen:
                    continue
                dest = hex_addr(remote)
                if dest.startswith(("127.", "[::1]", "[::ffff:127.")):
                    continue
                seen.add((local, remote))
                pid = pid_for_inode(inode) if inode != "0" else None
                info = proc_info(pid) if pid else {}
                info.setdefault("uid", uid)
                log("connect", dest=dest, state=TCP_STATES[state], **info)
        time.sleep(0.02)


def main() -> None:
    os.setpriority(os.PRIO_PROCESS, 0, -5)
    for target in (fanotify_loop, exec_loop, dns_loop, conn_loop):
        threading.Thread(target=target, daemon=True).start()
    log("watch_ready", what="watcher", pid=ME)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
