# Exercise 3 — Log Findings to a Database

**Goal:** Build a `findings` SQLite schema that captures the full demonstrate → remediate → re-test lifecycle, load Exercises 1 and 2's three findings into it, and prove the schema is useful by querying it.

**Estimated time:** 90 minutes.

## Before you start

Have Exercise 1 and Exercise 2's evidence files open — you'll be transcribing real values (risk scores, dates, outcomes) from them, not inventing new ones.

## Task 1 — Design the schema

Create `findings-schema.sql`. This table has to hold a finding at **any** point in its lifecycle — just demonstrated, or demonstrated and remediated, or demonstrated/remediated/re-tested — so most of the remediation-related columns must allow `NULL`:

```sql
CREATE TABLE findings (
    id                     INTEGER PRIMARY KEY,
    owasp_category         TEXT NOT NULL,   -- e.g. 'A01:2021-Broken Access Control'
    title                  TEXT NOT NULL,
    asset                  TEXT NOT NULL,   -- e.g. 'crunch-notes GET /notes/<note_id>'
    cwe                    TEXT,            -- e.g. 'CWE-639'
    likelihood             INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact                 INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score             INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
    demonstrated_at        TEXT NOT NULL,   -- ISO 8601 timestamp
    demonstrated_evidence  TEXT NOT NULL,   -- the request/response, or a path to it
    remediated_at          TEXT,
    remediation_summary    TEXT,
    retested_at            TEXT,
    retest_result          TEXT CHECK (retest_result IN ('pass', 'fail')),
    status                 TEXT NOT NULL DEFAULT 'open'
                             CHECK (status IN ('open', 'remediated', 'accepted_risk'))
);
```

Notes on the design, worth understanding before you load data:

- `risk_score` is a **generated column** — SQLite computes and stores `likelihood * impact` for you; you never insert it directly and it can never drift out of sync with the two inputs.
- `status` defaults to `'open'` because every finding starts life just-demonstrated, before any fix exists.
- `retest_result` is nullable because you can't have re-tested something you haven't fixed yet — a finding can be `demonstrated_at` filled and everything after it `NULL`, and that's a valid, in-progress row.

```bash
sqlite3 findings.db < findings-schema.sql
```

## Task 2 — Load Exercise 1 and Exercise 2's findings with Python

Write `load_findings.py`. Insert all **three** findings — the IDOR, the missing function-level check, and the misconfiguration — using the real values from your evidence files (your actual timestamps, your actual justified likelihood/impact numbers, not the illustrative ones below):

```python
import sqlite3

db = sqlite3.connect("findings.db")

findings = [
    {
        "owasp_category": "A01:2021-Broken Access Control",
        "title": "IDOR on GET /notes/<note_id>",
        "asset": "crunch-notes GET /notes/<note_id>",
        "cwe": "CWE-639",
        "likelihood": 4,
        "impact": 3,
        "demonstrated_at": "2026-07-20T14:02:00Z",
        "demonstrated_evidence": "alice.txt session read note_id=2 (bob's note); see evidence-idor.md",
        "remediated_at": "2026-07-20T14:40:00Z",
        "remediation_summary": "Added AND user_id = ? predicate to the notes lookup query.",
        "retested_at": "2026-07-20T14:45:00Z",
        "retest_result": "pass",
        "status": "remediated",
    },
    {
        "owasp_category": "A01:2021-Broken Access Control",
        "title": "Missing function-level check on GET /admin/users",
        "asset": "crunch-notes GET /admin/users",
        "cwe": "CWE-862",
        "likelihood": 4,
        "impact": 4,
        "demonstrated_at": "2026-07-20T14:10:00Z",
        "demonstrated_evidence": "alice.txt (role=user) listed all users incl. bob's admin role",
        "remediated_at": "2026-07-20T14:50:00Z",
        "remediation_summary": "Added require_role('admin') check before returning the user list.",
        "retested_at": "2026-07-20T14:52:00Z",
        "retest_result": "pass",
        "status": "remediated",
    },
    {
        "owasp_category": "A05:2021-Security Misconfiguration",
        "title": "Debug mode exposes Werkzeug interactive debugger",
        "asset": "crunch-notes GET /notes/<note_id> (any unhandled exception)",
        "cwe": "CWE-215",
        "likelihood": 3,
        "impact": 5,
        "demonstrated_at": "2026-07-20T15:05:00Z",
        "demonstrated_evidence": "GET /notes/not-a-number returned full stack trace + console; see debug-response.html",
        "remediated_at": None,
        "remediation_summary": None,
        "retested_at": None,
        "retest_result": None,
        "status": "open",
    },
]

for f in findings:
    db.execute(
        """
        INSERT INTO findings
            (owasp_category, title, asset, cwe, likelihood, impact,
             demonstrated_at, demonstrated_evidence,
             remediated_at, remediation_summary, retested_at, retest_result, status)
        VALUES
            (:owasp_category, :title, :asset, :cwe, :likelihood, :impact,
             :demonstrated_at, :demonstrated_evidence,
             :remediated_at, :remediation_summary, :retested_at, :retest_result, :status)
        """,
        f,
    )

db.commit()
db.close()
print("loaded 3 findings")
```

The third row is deliberately left `open` here — leave the misconfiguration's remediation fields `None` even though you actually fixed it in Exercise 2, so this exercise gives you practice querying a **mixed** open/remediated findings store. (You'll close it out for real in the mini-project.)

```bash
python3 load_findings.py
```

## Task 3 — Query it

Run each of these against `findings.db` and paste the output into `queries.md` along with one sentence per query on why that question matters to a real security team:

```sql
-- 1. Everything still open, highest risk first
SELECT title, owasp_category, risk_score, status
FROM findings
WHERE status != 'remediated'
ORDER BY risk_score DESC;

-- 2. Count of findings per OWASP category
SELECT owasp_category, COUNT(*) AS finding_count
FROM findings
GROUP BY owasp_category
ORDER BY finding_count DESC;

-- 3. Average risk score of everything demonstrated so far
SELECT ROUND(AVG(risk_score), 1) AS avg_risk_score FROM findings;

-- 4. Every finding that was remediated but never actually re-tested
-- (a common real-world gap: someone "fixed" it and never proved it)
SELECT title FROM findings
WHERE remediated_at IS NOT NULL AND retested_at IS NULL;
```

## Expected result (spot checks)

- `findings.db` has exactly 3 rows.
- Query 1 returns exactly the misconfiguration finding (the only one still `open`).
- Query 2 shows `A01:2021-Broken Access Control` with a count of 2.
- Query 4 returns zero rows for this load — both A01 findings have both `remediated_at` and `retested_at` filled in; if you see either of them here, re-check your inserted values.

## Done when…

- [ ] `findings-schema.sql`, `load_findings.py`, `findings.db`, and `queries.md` all exist.
- [ ] All three findings load without a constraint violation.
- [ ] `queries.md` has real output (not placeholder text) for all four queries, plus your one-sentence "why it matters" for each.
- [ ] You can explain, in one sentence, why `risk_score` is a generated column instead of a value you insert yourself.

## Stretch

- Add a `SELECT` that answers "what's my remediation rate?" — `remediated` count ÷ total count, as a percentage.
- Add a fourth finding of your own: something you noticed in `crunch-notes` while doing Exercises 1–2 that wasn't explicitly called out (there are seven more categories' worth of flaws still sitting in the app, per Lecture 2 and 3 — pick one you haven't fixed yet and log it as `status = 'open'`).

## Submission

Commit `findings-schema.sql`, `load_findings.py`, `findings.db`, and `queries.md` to your portfolio under `c50-week-03/exercise-03/`. This is the exact schema Challenge 1, Challenge 2, and the mini-project all extend — do not start over on a new schema later this week.
