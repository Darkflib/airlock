"""Check docs/SUBMISSION.md against the lablab form limits: python3 scripts/check-submission.py"""
import re
import sys
from pathlib import Path

text = Path(__file__).resolve().parents[1].joinpath("docs/SUBMISSION.md").read_text()
fields = dict(re.findall(r"^## (.+?)\n\n(.*?)(?=\n## |\Z)", text, re.S | re.M))
limits = {"Submission Title": (5, 50, 0), "Short Description": (50, 255, 0), "Long Description": (600, 2000, 100), "Additional Information": (0, 2000, 0)}
ok = True
for name, (lo, hi, words) in limits.items():
    body = fields[name].strip()
    n, w = len(body), len(body.split())
    good = lo <= n <= hi and w >= words
    ok &= good
    print(f"{'OK ' if good else 'BAD'} {name}: {n} chars (allowed {lo}-{hi}), {w} words" + (f" (min {words})" if words else ""))
sys.exit(0 if ok else 1)
