"""Join an escape-lab report with the outside catcher's log: did anything from a sandbox get there?

  scripts/catcher.sh log > hits.jsonl
  python evals/outside_count.py report.json hits.jsonl [--host-ip 78.141.205.99 --host-ip <v6>]

A contact counts against containment if it carries a run's token (DNS names arrive from resolvers
anywhere on the internet, so the source can't be the test) or comes from the Airlock host during a
run. The host-side control's marker must show up, or the catcher's silence proves nothing.
Prints a JSON summary on stdout.
"""

import argparse
import json


def text(hit: dict) -> str:
    """Everything in a hit a token could hide in, lowercased; ICMP payloads are decoded from hex."""
    body = hit.get("data", "")
    if hit.get("kind") == "icmp":
        body = bytes.fromhex(body).decode("latin-1")
    return f"{hit.get('name', '')} {body}".lower()


def carries(hit: dict, s: str) -> bool:
    """`ping -p` repeats only a 16-byte pattern, so an ICMP payload holds just the first 16 characters."""
    return bool(s) and (s in text(hit) or (hit.get("kind") == "icmp" and s[:16] in text(hit)))


def count(report: dict, hits: list[dict], host_ips: set[str]) -> dict:
    mark = (report.get("control") or {}).get("marker", "").lower()
    control = sorted({f"{h['kind']}:{h.get('proto') or h.get('port', '')}" for h in hits if carries(h, mark)})
    runs = []
    for i, run in enumerate(report["runs"], 1):
        token = run["probe_token"].lower() if "probe_token" in run else None
        lo, hi = run["window"]
        carried = [h for h in hits if token and carries(h, token)]
        # The two clocks differ by milliseconds, so the control (sent just before run 1) is named, not timed, out.
        from_host = [h for h in hits if h["peer"] in host_ips and lo <= h["t"] <= hi + 5 and not carries(h, mark)]
        runs.append({"run": i, "catcher_probes": sum(r["id"].startswith("catcher-") for r in run["probe"]),
                     "hits_with_token": carried, "hits_from_host": from_host})
    return {"catcher": report.get("catcher"), "control_seen": control, "control_sent": report.get("control"),
            "hits_total": len(hits), "runs": runs,
            "escaped": any(r["hits_with_token"] or r["hits_from_host"] for r in runs)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("hits")
    ap.add_argument("--host-ip", action="append", default=[], help="the Airlock host's public addresses")
    a = ap.parse_args()
    with open(a.report) as f:
        report = json.load(f)
    with open(a.hits) as f:
        hits = [json.loads(line) for line in f if line.strip()]
    print(json.dumps(count(report, hits, set(a.host_ip)), indent=2))
