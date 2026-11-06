#!/usr/bin/env python3
"""Time a voice-over take against the video script, line by line.

Record the whole narration in one take, then:

    python3 scripts/vo_timings.py take.m4a

It transcribes the take with whisper.cpp (word-level timestamps), aligns the
words with the quoted narration in docs/VIDEO_SCRIPT.md, and prints when each
line starts and ends next to the planned timing in docs/SHOT_LIST.md.
Whisper's word times run edge to edge, so line ends are trimmed to the start
of the next pause (ffmpeg silencedetect). A fluffed word or two is fine; if you
re-read a whole line, check its timing by hand: the alignment may pick either take.

Stdlib only. Needs ffmpeg and whisper-cli on PATH.
Env: WHISPER_MODEL (default ~/dev/whisper-dl/ggml-small.en.bin)
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "docs" / "VIDEO_SCRIPT.md"
SHOTS = ROOT / "docs" / "SHOT_LIST.md"
DEFAULT_MODEL = Path.home() / "dev" / "whisper-dl" / "ggml-small.en.bin"

# Narration lines in VIDEO_SCRIPT.md, in order, map to these shots in SHOT_LIST.md.
LINE_TO_SHOT = [str(n) for n in range(1, 14)] + ["14", "15"]

NUMBERS = {
    "33": "thirty three", "24": "twenty four", "3": "three", "9": "nine",
    "1": "one", "2": "two",
}


def words(text: str) -> list[str]:
    text = text.lower().replace("’", "'").replace("-", " ").replace("/", " ")
    out = []
    for w in re.findall(r"[a-z0-9']+", text):
        w = w.strip("'")
        if not w:
            continue
        out.extend(NUMBERS.get(w, w).split())
    return out


def narration_lines() -> list[str]:
    body = SCRIPT.read_text().split("## Shots and narration", 1)[1].split("## Cutaways", 1)[0]
    lines = [m.group(1) for m in re.finditer(r'^> "(.*)"\s*$', body, re.M)]
    if len(lines) != len(LINE_TO_SHOT):
        sys.exit(f"expected {len(LINE_TO_SHOT)} narration lines in {SCRIPT.name}, found {len(lines)}; "
                 "update LINE_TO_SHOT")
    return lines


def planned() -> dict[str, tuple[float, float]]:
    """Shot -> (in, out) seconds from the SHOT_LIST table; 14a/14b merge into 14."""
    def secs(t: str) -> float:
        m, s = t.split(":")
        return int(m) * 60 + float(s)

    plan: dict[str, tuple[float, float]] = {}
    for m in re.finditer(r"^\| (\d+)[ab]? \| (\d+:\d+)–(\d+:\d+) \|", SHOTS.read_text(), re.M):
        shot, a, b = m.group(1), secs(m.group(2)), secs(m.group(3))
        if shot in plan:
            a = min(a, plan[shot][0]); b = max(b, plan[shot][1])
        plan[shot] = (a, b)
    return plan


def silences(audio: Path) -> list[tuple[float, float]]:
    """Pauses of 0.3 s or more as [(start, end)]."""
    err = subprocess.run(["ffmpeg", "-hide_banner", "-i", str(audio), "-af",
                          "silencedetect=noise=-35dB:d=0.3", "-f", "null", "-"],
                         capture_output=True, text=True).stderr
    starts = [float(x) for x in re.findall(r"silence_start: ([\d.]+)", err)]
    ends = [float(x) for x in re.findall(r"silence_end: ([\d.]+)", err)]
    return list(zip(starts, ends + [float("inf")] * (len(starts) - len(ends))))


def transcribe(audio: Path, model: Path, keep: Path | None) -> list[tuple[str, float, float]]:
    """Return [(word, start_s, end_s)] for the take."""
    with tempfile.TemporaryDirectory() as tmp:
        wav = Path(tmp) / "take.wav"
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(audio), "-ac", "1", "-ar", "16000",
                        "-c:a", "pcm_s16le", str(wav)], check=True)
        base = Path(tmp) / "take"
        subprocess.run(["whisper-cli", "-m", str(model), "-f", str(wav), "-ml", "1", "-sow", "-np",
                        "-t", str(os.cpu_count() or 4), "-oj", "-of", str(base)],
                       check=True, stdout=subprocess.DEVNULL)
        data = json.loads((base.with_suffix(".json")).read_text())
        if keep:
            keep.write_text(json.dumps(data, indent=1))
    out = []
    for seg in data["transcription"]:
        a, b = seg["offsets"]["from"] / 1000, seg["offsets"]["to"] / 1000
        for w in words(seg["text"]):
            out.append((w, a, b))
    return out


def fmt(t: float | None) -> str:
    if t is None:
        return "  –  "
    m, s = divmod(t, 60)
    return f"{int(m)}:{s:04.1f}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("audio", type=Path, help="the voice-over take (any format ffmpeg reads)")
    ap.add_argument("--model", type=Path, default=Path(os.environ.get("WHISPER_MODEL", DEFAULT_MODEL)))
    ap.add_argument("--json", type=Path, help="also save whisper's raw JSON here")
    ap.add_argument("--from-json", type=Path, help="skip whisper; reuse a saved --json file")
    args = ap.parse_args()

    lines = narration_lines()
    script_words: list[tuple[str, int]] = [(w, i) for i, l in enumerate(lines) for w in words(l)]

    if args.from_json:
        data = json.loads(args.from_json.read_text())
        heard = [(w, s["offsets"]["from"] / 1000, s["offsets"]["to"] / 1000)
                 for s in data["transcription"] for w in words(s["text"])]
    else:
        if not args.model.exists():
            sys.exit(f"model not found: {args.model} (set WHISPER_MODEL)")
        heard = transcribe(args.audio, args.model, args.json)

    sm = difflib.SequenceMatcher(a=[w for w, _ in script_words], b=[w for w, _, _ in heard],
                                 autojunk=False)
    start: dict[int, float] = {}
    end: dict[int, float] = {}
    matched = [0] * len(lines)
    for blk in sm.get_matching_blocks():
        for k in range(blk.size):
            line = script_words[blk.a + k][1]
            _, a, b = heard[blk.b + k]
            start.setdefault(line, a)
            start[line] = min(start[line], a)
            end[line] = max(end.get(line, 0.0), b)
            matched[line] += 1

    # Whisper's word times run edge to edge, swallowing pauses. A line ends where the
    # pause that runs up to the next line begins; a line starts where the pause before it ends.
    # Whisper's times also run a few hundred ms late, hence the tolerance.
    tol = 0.6
    gaps = silences(args.audio)
    order = sorted(end)
    for i in order:  # snap starts first, so the end rule sees the corrected next start
        for a, b in gaps:
            if a < start[i] < b + tol:
                start[i] = b
    for k, i in enumerate(order):
        nxt = start[order[k + 1]] if k + 1 < len(order) else float("inf")
        for a, b in gaps:
            if start[i] < a < end[i] and b >= min(nxt, end[i]) - tol:
                end[i] = a

    plan = planned()
    total = [len(words(l)) for l in lines]
    print(f"{'shot':>4}  {'planned':>13} {'dur':>5}   {'heard':>13} {'speak':>5} {'slot':>5} {'Δ':>6}  match  line")
    starts = [start.get(i) for i in range(len(lines))]
    for i, line in enumerate(lines):
        shot = LINE_TO_SHOT[i]
        p = plan.get(shot)
        s, e = start.get(i), end.get(i)
        nxt = next((t for t in starts[i + 1:] if t is not None), e)
        slot = (nxt - s) if s is not None and nxt is not None else None
        pdur = p[1] - p[0] if p else None
        delta = f"{slot - pdur:+5.1f}" if slot is not None and pdur is not None else "     "
        pct = 100 * matched[i] // max(total[i], 1)
        speak = f"{e - s:5.1f}" if s is not None else "    –"
        print(f"{shot:>4}  {fmt(p[0]) if p else '':>6}–{fmt(p[1]) if p else '':<6} {pdur or 0:5.0f}   "
              f"{fmt(s):>6}–{fmt(e):<6} {speak} {slot or 0:5.1f} {delta}  {pct:3d}%   {line[:48]}")
    done = [t for t in end.values()]
    if done:
        print(f"\nlast word at {fmt(max(done))} (target 3:00). "
              "slot = this line's start to the next line's start (includes the pause); "
              "Δ = slot − planned duration.")
    low = [LINE_TO_SHOT[i] for i in range(len(lines)) if matched[i] < 0.6 * total[i]]
    if low:
        print(f"low match on shot(s) {', '.join(low)}: check the reading or the transcript (--json).")


if __name__ == "__main__":
    main()
