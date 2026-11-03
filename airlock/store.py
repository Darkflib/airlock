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
  decided REAL
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
        self.db.commit()

    def create_run(self, run_id: str, target: str, submitted_by: str | None = None) -> None:
        self.db.execute("INSERT INTO runs (id, target, status, created, submitted_by) VALUES (?, ?, 'queued', ?, ?)",
                        (run_id, target, time.time(), submitted_by))
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
