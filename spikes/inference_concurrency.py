"""How Vultr Serverless Inference latency changes with concurrent calls, with no VMs involved, to
separate inference slowdown from host CPU contention in the real-package load runs (build log 5 Nov).
Each call is about the size of a mid-run agent turn: a ~10k-token prompt and a short answer.

  scripts/remote.sh "uv run python spikes/inference_concurrency.py"
"""

import asyncio
import statistics
import time

from airlock.pipeline import inference_client, load_roles

LEVELS = (1, 4, 8, 12, 16)
CALLS = 16  # per level
FILLER = "\n".join(f"[E{i}] process_spawn: ran /usr/bin/node: node lib/module{i}.js --flag value-{i}" for i in range(900))


async def one(client, model: str, i: int) -> float:
    t0 = time.monotonic()
    await client.chat.completions.create(
        model=model, max_tokens=200, temperature=0.2, timeout=180,
        messages=[{"role": "system", "content": "You are a terse security reviewer."},
                  {"role": "user", "content": f"Run {i}. Events so far:\n{FILLER}\n\nIn two sentences: anything suspicious?"}])
    return time.monotonic() - t0


async def main() -> None:
    client, model = inference_client(), load_roles()["roles"]["agent"]
    for n in LEVELS:
        gate = asyncio.Semaphore(n)

        async def gated(i):
            async with gate:
                return await one(client, model, i)
        t0 = time.monotonic()
        lat = sorted(await asyncio.gather(*(gated(i) for i in range(CALLS))))
        wall = time.monotonic() - t0
        print(f"concurrency {n:2}: median {statistics.median(lat):5.1f} s  p90 {lat[int(0.9 * len(lat))]:5.1f} s  "
              f"max {lat[-1]:5.1f} s  {CALLS / wall * 60:5.1f} calls/min", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
