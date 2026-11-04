"""SQLite persistence for runs and their events. Small and synchronous: each
call is a single short statement, fine to run on the event loop."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .events import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  status TEXT NOT NULL,            -- queued | running | done | error
  verdict TEXT,
  evidence TEXT,                   -- JSON list
  model TEXT,
  error TEXT,
  submitted_by TEXT,
  decision TEXT,                   -- approved | rejected
  decided_by TEXT,
  meta TEXT,                       -- JSON: PR details, GitHub post results
  decision_note TEXT,
  created REAL NOT NULL,
  finished REAL,
  decided REAL,
  demo INTEGER                     -- 1: guests may read it even when an owner submitted it
);
CREATE TABLE IF NOT EXISTS events (
  run_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,
  summary TEXT NOT NULL,
  data TEXT NOT NULL,
  ts REAL NOT NULL,
  containment INTEGER NOT NULL,
  PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS selftests (
  id TEXT PRIMARY KEY,
  probes TEXT NOT NULL,            -- JSON list of {run_id, label, expect}
  submitted_by TEXT,
  created REAL NOT NULL
);
"""


def data_dir() -> Path:
    d = Path(os.environ.get("AIRLOCK_DATA", Path.home() / ".local" / "share" / "airlock"))
    d.mkdir(parents=True, exist_ok=True)
    return d


class Store:
    def __init__(self, path: Path | str | None = None):
        self.db = sqlite3.connect(path or data_dir() / "airlock.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(runs)")}
        for col in ("submitted_by", "decided_by", "meta"):
            if col not in cols:  # databases created before auth existed
                self.db.execute(f"ALTER TABLE runs ADD COLUMN {col} TEXT")
        if "demo" not in cols:
            self.db.execute("ALTER TABLE runs ADD COLUMN demo INTEGER")
        self.db.commit()

    def create_run(self, run_id: str, target: str, submitted_by: str | None = None, demo: bool = False) -> None:
        self.db.execute("INSERT INTO runs (id, target, status, created, submitted_by, demo) VALUES (?, ?, 'queued', ?, ?, ?)",
                        (run_id, target, time.time(), submitted_by, int(demo)))
        self.db.commit()

    def backfill_demo(self, guest_repos: frozenset[str]) -> None:
        """Runs from before the demo flag: only self-tests, npm specs and guest-repo PRs are demo."""
        rows = self.db.execute("SELECT id, target FROM runs WHERE demo IS NULL").fetchall()
        for run_id, target in rows:
            t = target.lower()
            demo = t.startswith("self-test:") or t.split("#")[0] in guest_repos or (
                "#" not in t and "/" not in t.lstrip("@").split("/", 1)[-1] and not t.endswith(".tgz"))
            self.db.execute("UPDATE runs SET demo = ? WHERE id = ?", (int(demo), run_id))
        self.db.commit()

    def update_run(self, run_id: str, **fields) -> None:
        for k in ("evidence", "meta"):
            if k in fields:
                fields[k] = json.dumps(fields[k])
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE runs SET {cols} WHERE id = ?", (*fields.values(), run_id))
        self.db.commit()

    def add_event(self, run_id: str, ev: Event) -> None:
        self.db.execute("INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (run_id, ev.id, ev.kind, ev.summary, json.dumps(ev.data, default=str), ev.ts,
                         int(ev.containment)))
        self.db.commit()

    def get_run(self, run_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT r.*, (SELECT COUNT(*) FROM events e WHERE e.run_id = r.id AND e.containment = 1"
            " AND COALESCE(json_extract(e.data, '$.stage'), '') != 'agent') AS contained "
            "FROM runs r WHERE id = ?", (run_id,)).fetchone()
        return _run(row) if row else None

    def list_runs(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            "SELECT r.*, (SELECT COUNT(*) FROM events e WHERE e.run_id = r.id AND e.containment = 1"
            " AND COALESCE(json_extract(e.data, '$.stage'), '') != 'agent') AS contained "
            "FROM runs r ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [_run(r) for r in rows]

    def append_event(self, run_id: str, kind: str, summary: str, **data) -> dict:
        """Add an event to a finished run (e.g. what was posted after the decision)."""
        seq = (self.db.execute("SELECT COALESCE(MAX(seq), 0) FROM events WHERE run_id = ?", (run_id,)).fetchone()[0]) + 1
        ev = Event(kind=kind, summary=summary, data=data, id=seq)
        self.add_event(run_id, ev)
        return ev.to_dict()

    def newer_run_of_commit(self, run: dict) -> str | None:
        """A later run of the same PR head commit. Its status supersedes this run's, so this
        run must no longer post to GitHub (its decision would overwrite the newer review)."""
        m = run.get("meta") or {}
        if not m.get("head_sha"):
            return None
        row = self.db.execute(
            "SELECT id FROM runs WHERE id != ? AND (created > ? OR (created = ? AND id > ?))"
            " AND json_extract(meta, '$.head_sha') = ? AND lower(json_extract(meta, '$.owner')) = lower(?)"
            " AND lower(json_extract(meta, '$.repo')) = lower(?) ORDER BY created DESC LIMIT 1",
            (run["id"], run["created"], run["created"], run["id"], m["head_sha"], m["owner"], m["repo"])).fetchone()
        return row[0] if row else None

    def run_of_commit(self, owner: str, repo: str, sha: str) -> str | None:
        """The latest run of a PR head commit that didn't fail, if any."""
        row = self.db.execute(
            "SELECT id FROM runs WHERE status != 'error' AND json_extract(meta, '$.head_sha') = ?"
            " AND lower(json_extract(meta, '$.owner')) = lower(?) AND lower(json_extract(meta, '$.repo')) = lower(?)"
            " ORDER BY created DESC LIMIT 1", (sha, owner, repo)).fetchone()
        return row[0] if row else None

    def count_targets(self, since: float, suffix: str) -> int:
        """Runs created since a time whose target label ends with `suffix` (e.g. webhook runs)."""
        return self.db.execute("SELECT COUNT(*) FROM runs WHERE created >= ? AND target LIKE ?",
                               (since, "%" + suffix)).fetchone()[0]

    def count_runs(self, since: float, user: str | None = None, exclude: frozenset[str] = frozenset()) -> int:
        """Runs created since a time, for one submitter, or for everyone not in `exclude` (case-insensitive)."""
        rows = self.db.execute("SELECT LOWER(COALESCE(submitted_by, '')) FROM runs WHERE created >= ?", (since,)).fetchall()
        names = [r[0] for r in rows]
        if user is not None:
            return names.count(user.lower())
        return sum(n not in exclude for n in names)

    def fail_stale_runs(self) -> int:
        """Runs left queued or running by a previous process can never finish: mark them failed."""
        cur = self.db.execute("UPDATE runs SET status = 'error', error = 'the server restarted during this run',"
                              " finished = ? WHERE status IN ('queued', 'running')", (time.time(),))
        self.db.commit()
        return cur.rowcount

    def proven_exfil(self, run_id: str) -> bool:
        """Whether the package itself (not the agent's re-runs) had exfiltration proven by a payload
        captured on the host (sinkhole request or DnsGuard lookup) carrying this run's canary token.
        Guest-side telemetry never counts."""
        return self.db.execute(
            "SELECT 1 FROM events WHERE run_id = ? AND json_extract(data, '$.proven') = 1"
            " AND json_extract(data, '$.this_run') = 1 AND json_extract(data, '$.source_kind') IN ('sinkhole', 'dns')"
            " AND COALESCE(json_extract(data, '$.stage'), '') != 'agent' LIMIT 1", (run_id,)).fetchone() is not None

    def create_selftest(self, test_id: str, probes: list[dict], submitted_by: str | None = None) -> None:
        self.db.execute("INSERT INTO selftests VALUES (?, ?, ?, ?)",
                        (test_id, json.dumps(probes), submitted_by, time.time()))
        self.db.commit()

    def get_selftest(self, test_id: str | None = None) -> dict | None:
        """One self-test by id, or the most recent when test_id is None."""
        row = (self.db.execute("SELECT * FROM selftests WHERE id = ?", (test_id,)) if test_id else
               self.db.execute("SELECT * FROM selftests ORDER BY created DESC LIMIT 1")).fetchone()
        return {**dict(row), "probes": json.loads(row["probes"])} if row else None

    def events(self, run_id: str, after: int = 0) -> list[dict]:
        rows = self.db.execute("SELECT * FROM events WHERE run_id = ? AND seq > ? ORDER BY seq",
                               (run_id, after)).fetchall()
        return [_event(r) for r in rows]


def _run(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
    d["meta"] = json.loads(d["meta"]) if d.get("meta") else {}
    return d


def _event(row: sqlite3.Row) -> dict:
    return {"id": row["seq"], "kind": row["kind"], "summary": row["summary"], "data": json.loads(row["data"]),
            "ts": row["ts"], "containment": bool(row["containment"])}
