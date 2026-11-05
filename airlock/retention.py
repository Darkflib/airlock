"""What the control plane keeps, and for how long. Every run's evidence (events, captured payloads,
verdict, decision) lives in the database, so the files around it are only working copies:

- an uploaded package is deleted when its run ends (and any left by a restart after a day);
- `sinkhole.jsonl` is rotated to `sinkhole.jsonl.1` once it is a day old or past 16 MB, but only while
  no VM on the host is running, since live runs read it by byte offset; the previous `.1` is dropped;
- runs that aren't demo runs (uploads, private packages, other repos) are deleted with their events
  after AIRLOCK_RETAIN_DAYS (30). Demo runs stay: share links and the public self-test point at them.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

from .store import Store

RETAIN_DAYS = float(os.environ.get("AIRLOCK_RETAIN_DAYS", "30"))
UPLOAD_ORPHAN_S = 86400
SINKHOLE_MAX_BYTES = 16 * 1024 * 1024
SINKHOLE_MAX_AGE_S = 86400
SWEEP_EVERY_S = 6 * 3600


def first_ts(log: Path) -> float | None:
    try:
        with open(log) as f:
            return float(json.loads(f.readline())["ts"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def rotate_sinkhole(log: Path, now: float) -> bool:
    """Rotate when big or old. The sinkhole opens the file by name for every record, so new records
    go to a fresh file; a Workspace that sees a new inode starts again from offset 0."""
    try:
        size = log.stat().st_size
    except FileNotFoundError:
        return False
    started = first_ts(log)
    if size == 0 or (size < SINKHOLE_MAX_BYTES and (started is None or now - started < SINKHOLE_MAX_AGE_S)):
        return False
    log.replace(log.with_name(log.name + ".1"))
    return True


async def sweep(store: Store, uploads: Path, sinkhole: Path, *, live: bool,
                vms_active: Callable[[], Awaitable[bool]] | None, now: float | None = None,
                retain_days: float = RETAIN_DAYS) -> dict:
    """One pass; returns what it removed. `live`: this service has runs in progress."""
    now = time.time() if now is None else now
    done = {"uploads": 0, "runs": 0, "sinkhole_rotated": False}
    for f in uploads.iterdir() if uploads.exists() else ():
        try:
            if f.is_file() and now - f.stat().st_mtime > UPLOAD_ORPHAN_S:
                f.unlink()
                done["uploads"] += 1
        except FileNotFoundError:
            pass
    done["runs"] = store.prune_runs(now - retain_days * 86400)
    if not live and vms_active is not None and not await vms_active():
        done["sinkhole_rotated"] = rotate_sinkhole(sinkhole, now)
    return done
