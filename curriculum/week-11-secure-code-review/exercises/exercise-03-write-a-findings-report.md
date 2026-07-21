# Exercise 3 — Write a Findings Report

**Goal:** Turn Exercise 2's two traces into full, seven-field findings following Lecture 3's template, insert them into `review_findings.db`, and run the summary queries that make a review's status answerable in SQL instead of a memory of which Slack thread had the details.

**Estimated time:** 90 minutes.

## Setup

```bash
cd crunch-invoices/c50-week-11/exercise-03
```

Bring `trace-injection.md` and `trace-authz.md` from Exercise 2 into this folder — you're writing from your own traces, not re-deriving them.

## Task 1 — Build the findings table (10 min)

Create `review_findings_schema.sql` (Lecture 3, Section 5's schema, reproduced exactly):

```sql
CREATE TABLE review_findings (
    finding_id       INTEGER PRIMARY KEY,
    app_name         TEXT NOT NULL DEFAULT 'crunch-invoices',
    location         TEXT NOT NULL,
    cwe              TEXT NOT NULL,
    category         TEXT NOT NULL CHECK (category IN
        ('injection','authn','authz','crypto','secrets','config','other')),
    severity         TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    reproduction     TEXT NOT NULL,
    impact           TEXT NOT NULL,
    recommended_fix  TEXT NOT NULL,
    discovered_by    TEXT NOT NULL,
    discovered_at    TEXT NOT NULL DEFAULT (datetime('now')),
    status           TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','fixed','wontfix','false_positive','retested_ok')),
    resolved_at      TEXT
);
```

```bash
sqlite3 review_findings.db < review_findings_schema.sql
```

## Task 2 — Write the full findings (45 min)

Using Lecture 3 Section 2's seven-field template, write out **at least four** findings in `findings-report.md`, each covering ground your Exercise 1/2 work already established:

1. **The SQL injection** in `/invoices/search` (from `trace-injection.md`).
2. **The missing authentication check** on `/invoices/search` — remember Lecture 3's worked example split this from the injection as an independent finding even though it's the same route; do the same here.
3. **The missing authorization (role + account) check** on `/invoices/export` (from `trace-authz.md`).
4. At least one finding of your choice from the download-link routes, informed by Lecture 2 Section 4 — pick **one** of the three independent crypto/secrets findings there (hardcoded key, homemade MD5 MAC, or non-constant-time compare) and write it up fully; you don't need all three yet (Challenge 1 covers the rest).

Each finding needs a **real** reproduction — an actual command and actual output, not a placeholder — and a severity assigned from Lecture 3 Section 3's rubric, with one clause explaining which cell of the table you landed on and why.

## Task 3 — Insert every finding into the database (20 min)

For each finding in `findings-report.md`, write and run an `INSERT` into `review_findings.db`, following Lecture 3 Section 5's example exactly (all thirteen columns except the auto `finding_id` and default `discovered_at`/`status`). Set `discovered_by` to your own name or handle.

## Task 4 — Query your own evidence (15 min)

Write and run, in `queries.sql`:

1. **Everything currently open**, worst severity first (Lecture 3 Section 5's `CASE`-ordered query, reproduced or adapted).
2. **Count of findings by `category`** — how many injection vs. authz vs. crypto/secrets findings did this review surface?
3. **Count of findings by `severity`** — how many critical, how many high, etc.
4. A query of your own devising that answers a question you'd actually want answered about this review (e.g., "which findings share the same `location`?" or "which CWE appears more than once?").

## Done when…

- [ ] `review_findings.db` has at least 4 rows, each with all thirteen non-default columns filled in with real content (not `"TODO"` or a template placeholder anywhere).
- [ ] Every `reproduction` field contains an actual command and actual output you ran, matching what's in your Exercise 1/2 files.
- [ ] Every `severity` is defensible from Lecture 3 Section 3's rubric — you can state, for each, which cell it landed in and why.
- [ ] All four queries in `queries.sql` run without error and return sensible results you can explain.
- [ ] No two independent findings (per Lecture 3 Section 2's rule) were merged into one row to save time.

## Stretch

- Write a query that would flag, for any *future* review of this same app, whether a given `location` has ever had a `critical` finding — a lightweight "this file has a history" signal, the kind a real security team tracks across repeated reviews.
- Draft the `fix_description`/re-test update for one finding as if you'd already applied the fix (you'll actually do this for real in the mini-project) — write the `UPDATE ... SET status = 'retested_ok', resolved_at = datetime('now')` statement you'd run once the fix lands.

## Submission

Commit `review_findings_schema.sql`, `review_findings.db`, `findings-report.md`, and `queries.sql` to your portfolio under `c50-week-11/exercise-03/`. Challenge 1 extends this same database to a full-app review; the mini-project carries it through to resolution.
