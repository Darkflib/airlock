# Run 1 vs run 2 — datadog-sample-20261108T123757Z vs datadog-sample-20261108T142051Z

The same 680 packages, run twice. Run 1 had fake credentials in files only; run 2 added fake tokens in the install environment and a fake SSH key. Everything else was the same code.

| | Run 1 | Run 2 | Only in run 1 | Only in run 2 | Run-to-run spread (1 SD) | p-value |
| --- | --- | --- | --- | --- | --- | --- |
| Proven credential theft | 6 (0.9%, 0–2%) | 27 (4.0%, 3–6%) | 0 | 21 | ±0.7 points | below 0.0001 |
| Called malicious | 518 (76.2%, 73–79%) | 529 (77.8%, 75–81%) | 4 | 15 | ±0.6 points | 0.02 |
| Called malicious or suspicious | 593 (87.2%, 84–90%) | 580 (85.3%, 82–88%) | 29 | 16 | ±1.0 points | 0.07 |
| Called benign (a miss) | 71 (10.4%, 8–13%) | 83 (12.2%, 10–15%) | 14 | 26 | ±0.9 points | 0.08 |

**In plain terms.**

- **Proven theft went from 6 to 27.** 21 packages were proven only with the new fake tokens and 0 only without them. The p-value, below 0.0001, is the chance of a split that lopsided if the new tokens made no difference at all. That chance is tiny, so the tokens really do catch more.
- **The AI's verdict wobbles between runs.** 63 of 680 packages (9%) got a different verdict the second time. For *called malicious* that's a spread of about ±0.6 percentage points from one run to the next (one standard deviation, SD). The move from 76.2% to 77.8% has a p-value of 0.02: small enough that it's probably real, and it matches the extra proof, since proven theft is malicious whatever the AI says. Proof doesn't wobble the same way: fixed rules decide it from the captured request, not the model.
- **The ranges in brackets** (for example 74–79%) are 95% intervals: if we drew another sample of this size from the same dataset, the rate would usually land inside them.
- **How to read a p-value:** below 0.05 is the usual bar for "probably a real effect"; below 0.01 is strong. Above that, treat the difference as noise.
