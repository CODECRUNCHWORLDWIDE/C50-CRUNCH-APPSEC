# Exercise 3 — Triage Findings into a Database

**Goal:** Extend your Week 1 `appsec.db` with `scanners` and `findings` tables, load real output from Semgrep, ZAP, and Trivy into one unified schema, normalize each tool's own severity vocabulary onto a shared scale, and query the combined backlog — the payoff for every prior exercise this week.

**Estimated time:** 90 minutes.

## Why one schema for three tools

Three scanners, three JSON shapes, three severity vocabularies (`ERROR`/`WARNING`/`INFO`, `High`/`Medium`/`Low`, `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`). If you keep three separate files or three separate tables, "what should I fix first, across everything?" requires manually cross-referencing three documents by hand — exactly the failure this course's data-tooling rule exists to prevent. One `findings` table, one normalized severity column, one `ORDER BY risk_score DESC` answers it instantly, forever, as new scans come in.

## Setup

```bash
cd c50-week-08/exercise-03
cp ../exercise-01/semgrep-results.json .
cp ../exercise-02/zap-reports/full-report.json .
```

You'll also need a Trivy scan for the SCA leg — run it now if you haven't:

```bash
trivy fs --scanners vuln --format json --output trivy-results.json ../exercise-01/juice-shop-src/
```

Copy forward your `appsec.db` from a previous week (it should already have `targets`, `attack_surface`, and `risks`):

```bash
cp ~/portfolio/c50-week-01/exercise-02/appsec.db .   # adjust path to wherever you've kept it
sqlite3 appsec.db "PRAGMA foreign_keys = ON;"
```

## Task 1 — Extend the schema

Create `schema-extend.sql`:

```sql
CREATE TABLE scanners (
    scanner_id   INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    category     TEXT NOT NULL CHECK (category IN ('sast','dast','sca')),
    version      TEXT
);

CREATE TABLE findings (
    finding_id       INTEGER PRIMARY KEY,
    scanner_id       INTEGER NOT NULL REFERENCES scanners(scanner_id),
    target_id        INTEGER NOT NULL REFERENCES targets(target_id),
    rule_id          TEXT NOT NULL,
    title            TEXT NOT NULL,
    severity_raw     TEXT NOT NULL,
    severity_normal  TEXT NOT NULL
                        CHECK (severity_normal IN ('info','low','medium','high','critical')),
    file_path        TEXT,
    line_number      INTEGER,
    url              TEXT,
    cve_id           TEXT,
    package_name     TEXT,
    package_version  TEXT,
    description      TEXT NOT NULL,
    raw_output       TEXT,
    status           TEXT NOT NULL DEFAULT 'new'
                        CHECK (status IN ('new','confirmed','false_positive','duplicate','wontfix','fixed')),
    triage_notes     TEXT,
    likelihood       INTEGER CHECK (likelihood BETWEEN 1 AND 5),
    impact           INTEGER CHECK (impact BETWEEN 1 AND 5),
    risk_score       INTEGER,
    discovered_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO scanners (name, category, version) VALUES
  ('semgrep', 'sast', 'auto-config'),
  ('zap', 'dast', 'zap-stable-docker'),
  ('trivy', 'sca', 'latest');
```

```bash
sqlite3 appsec.db < schema-extend.sql
```

## Task 2 — Load Semgrep (SAST) findings

Write `load_semgrep.py`. The core of the exercise is the **severity mapping** — decide, and justify in a comment, how Semgrep's three-level scale maps onto the five-level `severity_normal` scale:

```python
import json, sqlite3

conn = sqlite3.connect("appsec.db")
cur = conn.cursor()

target_id = cur.execute(
    "SELECT target_id FROM targets WHERE name = ?", ("juice-shop",)
).fetchone()[0]
scanner_id = cur.execute(
    "SELECT scanner_id FROM scanners WHERE name = 'semgrep'"
).fetchone()[0]

# Semgrep's own scale has no direct "critical" or "info"-only distinction beyond these three —
# ERROR is treated as high-severity by default here; a real team would refine this per-rule
# using the rule's own `metadata.confidence`/`metadata.likelihood` fields where present.
SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}

with open("semgrep-results.json") as f:
    data = json.load(f)

rows = []
for r in data["results"]:
    sev_raw = r["extra"]["severity"]
    rows.append((
        scanner_id, target_id,
        r["check_id"],
        r["check_id"].split(".")[-1].replace("-", " ").title(),
        sev_raw, SEVERITY_MAP.get(sev_raw, "medium"),
        r["path"], r["start"]["line"],
        None, None, None, None,
        r["extra"]["message"],
        json.dumps(r),
    ))

cur.executemany(
    """INSERT INTO findings
       (scanner_id, target_id, rule_id, title, severity_raw, severity_normal,
        file_path, line_number, url, cve_id, package_name, package_version,
        description, raw_output)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
    rows,
)
conn.commit()
print(f"Loaded {len(rows)} Semgrep findings.")
conn.close()
```

```bash
python3 load_semgrep.py
```

## Task 3 — Load ZAP (DAST) and Trivy (SCA) findings

Write `load_zap.py` and `load_trivy.py` following the same pattern as Task 2 — parse each tool's native JSON shape, map its severity vocabulary onto `severity_normal` (ZAP's alerts carry a `risk` field like `"High"`/`"Medium"`/`"Low"`/`"Informational"`; Trivy's `Vulnerabilities[].Severity` is `"CRITICAL"`/`"HIGH"`/`"MEDIUM"`/`"LOW"`), and insert into `findings` with the scanner-specific columns populated (`url` for ZAP, `cve_id`/`package_name`/`package_version` for Trivy, both left `NULL` for the other tool's rows).

**Do not skip writing your own severity-mapping table for each tool** — a defensible mapping (documented in a comment, like Task 2's) is part of this exercise's grade, not a mechanical afterthought. ZAP's `"Informational"` maps to `info`; Trivy's `"CRITICAL"` maps to `critical` — but the middle bands deserve a real decision, written down.

## Task 4 — Query the combined backlog

Write and run each in `queries.sql`:

1. **Everything, ranked by normalized severity** (`CASE severity_normal WHEN 'critical' THEN 5 WHEN 'high' THEN 4 ...` — build the ordering explicitly, since it's alphabetically wrong otherwise).
2. **Count of findings per scanner category** (`sast`/`dast`/`sca`) — which tool produced the most raw noise?
3. **All SCA findings with no `FixedVersion` available** — join in a hint at fix availability via `description` or a note you add — these are the hardest to remediate quickly and deserve special flagging.
4. **All findings still `status = 'new'`** — your remaining triage backlog after this exercise.
5. **A single query proving no `false_positive` row has a `NULL` or empty `triage_notes`** — this should return zero rows in a properly disciplined backlog; if it doesn't yet, that's expected at this stage (you haven't triaged everything), but the query itself must exist and be correct.

## Task 5 — Triage ten more findings

Pick ten `status = 'new'` rows spanning at least two different scanners, and `UPDATE` each to `confirmed` or `false_positive` with a real `triage_notes` justification and (for confirmed rows) a `likelihood`/`impact`/`risk_score`. Save these as `triage-updates.sql`.

## Expected result (spot checks)

- Query 1 should show at least one `critical` or `high` entry from at least two different scanner categories.
- Query 5 (the false-positive-notes check) must return zero rows — it's a data-integrity check on your own discipline, not a difficult query.
- After Task 5, `SELECT COUNT(*) FROM findings WHERE status != 'new'` should be at least 10.

## Done when…

- [ ] `findings` table has rows from all three scanners (`SELECT scanner_id, COUNT(*) FROM findings GROUP BY scanner_id` shows three non-zero rows).
- [ ] Every severity mapping decision is documented in a comment in its loader script, not left implicit.
- [ ] All 5 queries in `queries.sql` run and return sensible results, including the zero-row integrity check.
- [ ] `triage-updates.sql` moves at least 10 findings out of `status = 'new'`, each with real `triage_notes`.

## Stretch

- Add a `duplicate_of` column (nullable foreign key to `finding_id`) and use it to link one Semgrep finding to a Trivy finding you believe describe the same underlying weakness (Lecture 3, Section 4's reconciliation problem) — this is direct practice for Challenge 2.
- Write one query that computes, per scanner, the **false-positive rate** among findings you've triaged so far (`false_positive` count / total triaged count) — a real, if early, signal about which tool needs the most manual double-checking in your specific app.

## Submission

Commit `schema-extend.sql`, `load_semgrep.py`, `load_zap.py`, `load_trivy.py`, `queries.sql`, `triage-updates.sql`, and the updated `appsec.db` to your portfolio under `c50-week-08/exercise-03/`. This database is what the mini-project extends into a final, complete backlog.
