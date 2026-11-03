"""Local UI dev server: replays recorded runs instead of booting microVMs.
No KVM, inference key or sign-in needed.

  uv run python scripts/ui_replay.py [port]
Then submit `hostile` or `benign` (fixtures in tests/fixtures/runs/) from the page.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import uvicorn

from airlock.store import Store
from airlock.web.app import create_app

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "runs"


async def replay(target, *, events, **_):
    run = json.loads((FIXTURES / f"{target.split('@')[0]}.json").read_text())
    prev = run["events"][0]["ts"]
    for ev in run["events"]:
        await asyncio.sleep(min(ev["ts"] - prev, 1.5))  # real pacing, long gaps capped
        prev = ev["ts"]
        events.emit(ev["kind"], ev["summary"], **ev["data"])
    return SimpleNamespace(verdict=run["verdict"], evidence=run["evidence"], model=run["model"])


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    tmp = Path(tempfile.mkdtemp(prefix="airlock-ui-"))
    import os
    os.environ["AIRLOCK_DATA"] = str(tmp)
    app = create_app(store=Store(tmp / "replay.db"), analyse=replay)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
