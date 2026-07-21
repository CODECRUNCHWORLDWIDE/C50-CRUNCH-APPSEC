# Exercise 1 — Run a SAST Scan

**Goal:** Run Semgrep against the published source of your own lab target (Juice Shop), then hand-triage five real findings yourself — the step that keeps you from ever blindly trusting a tool's verdict, this week or in your career.

**Estimated time:** 90 minutes.

## Why hand-triage before automating anything

It's tempting to jump straight to "load everything into a database and let queries sort it out." Do this exercise's manual pass first anyway: you cannot judge whether an automated triage pipeline (Exercise 3) is working correctly unless you already know, from your own reading, what a handful of real findings actually mean. This exercise is where that ground truth comes from.

## Setup

```bash
mkdir -p c50-week-08/exercise-01 && cd c50-week-08/exercise-01
semgrep --version   # confirm installed; if not: pip install semgrep
```

Clone Juice Shop's published source — this is the source code of your own Week 1 lab target, publicly available by design, not a third-party system:

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git juice-shop-src
```

## Task 1 — Run the scan

```bash
cd juice-shop-src
semgrep --config=auto --json --output=../semgrep-results.json .
cd ..
```

This will take a minute or two. Semgrep prints a text summary to your terminal — note the total finding count and how many rules were applied before moving on.

## Task 2 — Summarize with Python

Write `summarize.py`:

```python
import json
from collections import Counter

with open("semgrep-results.json") as f:
    data = json.load(f)

results = data["results"]
print(f"Total findings: {len(results)}")

by_severity = Counter(r["extra"]["severity"] for r in results)
print("By severity:", dict(by_severity))

by_rule = Counter(r["check_id"] for r in results)
print("\nTop 10 rules by finding count:")
for rule, count in by_rule.most_common(10):
    print(f"  {count:>3}  {rule}")
```

```bash
python3 summarize.py
```

## Task 3 — Hand-triage five real findings

Pick **five** findings from `semgrep-results.json` — deliberately choose a mix, not the five easiest ones: at least one `ERROR`-severity finding, at least one you suspect might be a false positive, and at least one involving a route or file you haven't looked at yet. For each, open `semgrep-results.json`, find the entry, and open the actual source file at the reported `start.line`.

Write `triage-notes.md` with one section per finding, each answering:

1. **What is the rule claiming?** (paraphrase `extra.message` in your own words — if you can't paraphrase it, you don't understand it yet)
2. **Read the code at that exact line, plus ~10 lines of surrounding context.** Is there a source-to-sink taint flow that actually exists, the way Lecture 1, Section 2 traced one? Or is the "dangerous" call actually protected by something Semgrep's rule didn't recognize (a sanitizer, a type that makes the concern moot, dead code)?
3. **Verdict:** `TRUE POSITIVE` or `FALSE POSITIVE`, with your reasoning stated in a full sentence — not just the label.

## Expected result (spot checks)

- Your total finding count should be in the dozens at minimum — if Semgrep returns 0 or 1 result, something is misconfigured (check you ran it from inside `juice-shop-src`, and that `--config=auto` actually detected JavaScript/TypeScript files).
- At least one of your five hand-triaged findings should turn out to be a genuine true positive with a traceable source-to-sink path you can point to by file and line number.
- At least one should have a defensible false-positive argument — if all five look equally "definitely real" to you without genuine investigation, look harder; Semgrep's `auto` ruleset is known to be broad, and not every match is exploitable in context.

## Done when…

- [ ] `semgrep-results.json` exists with dozens of results.
- [ ] `summarize.py` runs and prints a severity breakdown and a top-10-rules list.
- [ ] `triage-notes.md` has five findings, each with a paraphrased claim, your code reading, and a one-sentence-justified verdict.
- [ ] You can explain, from memory, the difference between "this rule fired" and "this is a confirmed true positive" — the exact distinction Lecture 1, Section 6 draws between scanner severity and your own judgment.

## Stretch

- Write a second Python script that filters `semgrep-results.json` down to only findings tagged with an OWASP or CWE metadata field, and count how many map to categories you've already studied in Weeks 3–7 (injection, broken auth, etc.) — a concrete look at how this week's tooling overlaps with everything you've learned by hand so far.
- Try `--config=p/owasp-top-ten` instead of `--config=auto` and compare the finding count and overlap — which ruleset is broader, and why might a team choose the narrower one for CI?

## Submission

Commit `semgrep-results.json`, `summarize.py`, and `triage-notes.md` to your portfolio under `c50-week-08/exercise-01/`. Keep `semgrep-results.json` exactly as produced — Exercise 3 loads it directly into your findings database.
