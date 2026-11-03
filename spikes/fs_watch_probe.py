"""Spike: can the guest kernel tell us who touched the canary files?

Run inside a sandbox as root:  python3 fs_watch_probe.py
Tests inotify (no pid) and fanotify (pid), plus what tracing/eBPF plumbing exists.
"""

import ctypes
import os
import struct
import subprocess
import time

libc = ctypes.CDLL(None, use_errno=True)
CANARY = "/root/.aws/credentials"
os.makedirs("/root/.aws", exist_ok=True)
open(CANARY, "w").write("[default]\naws_access_key_id = AKIATEST\n")


def err() -> str:
    return os.strerror(ctypes.get_errno())


# --- inotify ---------------------------------------------------------------
IN_ACCESS, IN_OPEN = 0x1, 0x20
ifd = libc.inotify_init1(os.O_NONBLOCK)
wd = libc.inotify_add_watch(ifd, CANARY.encode(), IN_ACCESS | IN_OPEN)
print("inotify: init", ifd, "watch", wd, err() if wd < 0 else "")

# --- fanotify ----------------------------------------------------------------
FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_NONBLOCK = 0x0, 0x1, 0x2
FAN_ACCESS, FAN_OPEN, FAN_OPEN_EXEC = 0x1, 0x20, 0x1000
FAN_MARK_ADD, FAN_MARK_MOUNT = 0x1, 0x10
ffd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY)
print("fanotify: init", ffd, err() if ffd < 0 else "")
if ffd >= 0:
    rc = libc.fanotify_mark(ffd, FAN_MARK_ADD, ctypes.c_uint64(FAN_OPEN | FAN_ACCESS), -100, CANARY.encode())
    print("fanotify: mark file", rc, err() if rc < 0 else "")
    rc2 = libc.fanotify_mark(ffd, FAN_MARK_ADD | FAN_MARK_MOUNT, ctypes.c_uint64(FAN_OPEN_EXEC), -100, b"/")
    print("fanotify: mark mount for exec", rc2, err() if rc2 < 0 else "")

# Something that is not us, and not Node, reads the canary and runs a program.
subprocess.run(["sh", "-c", f"cat {CANARY} >/dev/null; /usr/bin/env true"])
time.sleep(0.2)

try:
    data = os.read(ifd, 4096)
    events = []
    while data:
        wd_, mask, _, ln = struct.unpack_from("iIII", data)
        events.append(hex(mask))
        data = data[16 + ln:]
    print("inotify: events", events)
except BlockingIOError:
    print("inotify: no events")

if ffd >= 0:
    try:
        buf = os.read(ffd, 8192)
        off = 0
        while off < len(buf):
            ev_len, ver, _, meta_len, mask, fd, pid = struct.unpack_from("IBBHQii", buf, off)
            path = os.readlink(f"/proc/self/fd/{fd}") if fd >= 0 else "?"
            try:
                comm = open(f"/proc/{pid}/comm").read().strip()
            except OSError:
                comm = "(exited)"
            print(f"fanotify: mask={hex(mask)} pid={pid} comm={comm} path={path}")
            if fd >= 0:
                os.close(fd)
            off += ev_len
    except BlockingIOError:
        print("fanotify: no events")

# --- tracing / eBPF plumbing ----------------------------------------------------
for p in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing", "/sys/kernel/btf/vmlinux", "/sys/fs/bpf"):
    print("exists" if os.path.exists(p) else "absent", p)
try:
    syms = open("/proc/kallsyms").read()
    for s in ("bpf_prog_run", "register_kprobe", "bpf_trace_printk", "security_file_open"):
        print("kallsyms", s, "yes" if f" {s}\n" in syms or f" {s}\t" in syms else "no")
except OSError as e:
    print("kallsyms", e)
BPF_PROG_LOAD = 5
rc = libc.syscall(321, BPF_PROG_LOAD, None, 0)  # expect EINVAL/EFAULT if bpf() exists, ENOSYS if not
print("bpf syscall:", rc, err())
