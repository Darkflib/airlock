import json

from airlock.events import EventLog, events_from_trace

ALLOW = ("registry.npmjs.org",)
NPM = "/usr/local/lib/node_modules/npm/bin/npm-cli.js install /work/candidate.tgz"
POST = "/tmp/try/node_modules/left-padder/postinstall.js"


def line(**kw) -> str:
    return json.dumps({"ts": 1, "pid": 1, **kw})


def kinds(trace: str) -> list[str]:
    return [k for k, _, _ in events_from_trace(trace, ALLOW)]


def test_ignores_npm_own_activity():
    trace = "\n".join([
        line(argv=NPM, ev="file_read", path="/root/.npmrc"),
        line(argv=NPM, ev="net_request", host="registry.npmjs.org"),
    ])
    assert kinds(trace) == []


def test_postinstall_canary_read_and_blocked_egress():
    trace = "\n".join([
        line(argv=POST, ev="file_read", path="/root/.npmrc"),
        line(argv=POST, ev="file_read", path="/root/.aws/credentials"),
        line(argv=POST, ev="net_request", host="collector.airlock-demo.invalid"),
        line(argv=POST, ev="net_payload_canary", host="collector.airlock-demo.invalid"),
    ])
    assert kinds(trace) == ["canary_read", "canary_read", "egress_blocked", "canary_exfil"]


def test_allowlisted_host_is_not_containment():
    assert kinds(line(argv=POST, ev="net_request", host="registry.npmjs.org:443")) == ["egress_allowed"]


def test_dedupes_repeated_lines_and_skips_garbage():
    rec = line(argv=POST, ev="file_read", path="/root/.npmrc")
    assert kinds("\n".join([rec, rec, "not json"])) == ["canary_read"]


def test_eventlog_ids_and_containment_flag():
    log = EventLog()
    log.emit("exec", "$ ls")
    ev = log.emit("canary_read", "read ~/.npmrc")
    assert ev.id == 2 and ev.containment and not log.events[0].containment
    assert [e.kind for e in log.containment()] == ["canary_read"]
