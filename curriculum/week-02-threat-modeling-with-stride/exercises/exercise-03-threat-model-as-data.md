# Exercise 3 — Threat Model as Data

**Goal:** Turn Exercise 2's threat list into a real, queryable SQLite database — schema, load script, and a set of risk-register queries — so "what's our top risk?" is a query you run, not a document you scroll.

**Estimated time:** 90 minutes.

## Setup

Have `stride-pass.md` from Exercise 2 open — you're about to transcribe it into structured data. Confirm Python and SQLite are available:

```bash
python3 --version          # 3.10+
python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
```

## Tasks

1. **Create `schema.sql`** with the two tables from Lecture 3, Section 4 (`elements` and `threats`), exactly as shown — including the `CHECK` constraints and the generated `risk_score` column. Run it once to confirm it's valid SQL:

   ```bash
   sqlite3 threatmodel.db < schema.sql
   sqlite3 threatmodel.db ".schema"     # sanity check — both tables print
   ```

2. **Populate `elements`**, one row per element from your Exercise 1 diagram. Do this directly in SQL or Python — your choice — but every element from your diagram must appear.

3. **Write `load_threats.py`** — a Python script using the `sqlite3` module (not the CLI) that inserts every threat from your Exercise 2 list. For each threat, you must now assign:
   - A **likelihood** and **impact** score (1–5 each), using Lecture 3 Section 1's rubric.
   - A **disposition** (mitigate / eliminate / transfer / accept), using Lecture 3 Section 2.
   - A **mitigation** string — expand your Exercise 2 one-clause direction into one full sentence.

   Run it: `python3 load_threats.py`. Confirm the row count matches your Exercise 2 list:

   ```bash
   sqlite3 threatmodel.db "SELECT COUNT(*) FROM threats;"
   ```

4. **Write `queries.sql`** containing at least these five queries, each preceded by a comment explaining what question it answers:
   - Top 5 threats by `risk_score`, open only.
   - Count of open threats grouped by `stride_category`.
   - Every threat where `disposition = 'accept'` (the risks being knowingly carried).
   - Every threat attached to a specific element of your choice (e.g., "every threat on the login process").
   - Average `risk_score` per element — which single element is, on average, the riskiest across all its threats?

5. **Run every query and save the output** — either by piping to a file or pasting into `results.md` alongside the query that produced it.

6. **Reflect (3–4 sentences) in `results.md`:** Now that the data is queryable, what's one question you could answer in seconds that would have taken real effort to answer from `stride-pass.md` alone?

## Deliverable

A folder containing:
- `schema.sql`
- `load_threats.py`
- `queries.sql`
- `threatmodel.db` (the populated database file)
- `results.md` (query outputs + the Task 6 reflection)

## Done when…

- [ ] `sqlite3 threatmodel.db ".schema"` shows both tables with the `CHECK` constraints intact.
- [ ] `SELECT COUNT(*) FROM threats;` returns 15+ (matching Exercise 2's minimum).
- [ ] Every threat has a non-null `likelihood`, `impact`, `disposition`, and `mitigation` — no placeholders.
- [ ] All five required queries run without error and their output is captured in `results.md`.
- [ ] The top-5-by-risk query's #1 result is your Exercise 2 "scariest threat" — if it isn't, go back and check whether your likelihood/impact scoring was too conservative, or your Exercise 2 instinct was off. Either is a valid finding, but you must reconcile the two, not ignore the mismatch.

## Stretch

- Add a `queries.sql` entry that finds every threat whose `disposition = 'mitigate'` but `status = 'open'` **and** `risk_score >= 15` — the "should be fixed soon" list a team would actually triage from first.
- Write a second Python script, `report.py`, that runs the top-5 query and prints a clean Markdown table to stdout — the beginning of an automated risk-report generator you'll extend in the mini-project.

## Submission

Keep the whole folder in `week-02-exercises/exercise-03/` in your portfolio. This database is the foundation the mini-project extends into a full report.
