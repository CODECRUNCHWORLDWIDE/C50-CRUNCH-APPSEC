# Exercise 3 — Generate and Scan an SBOM

**Goal:** Generate a CycloneDX software bill of materials for `crunch-tasks-api`'s dependencies, scan it for known vulnerabilities with `pip-audit`, and load the findings into a queryable SQLite database.

**Estimated time:** 90 minutes.

## Before you start

`crunch-tasks-api`'s virtual environment from the week README, with `flask==3.0.3` installed. Install the scanner:

```bash
pip install pip-audit
```

## Task 1 — Pin your dependencies properly

`crunch-tasks-api`'s `requirements.txt` so far has only ever existed as a `pip install` command in the README. Freeze it into a real, pinned file first — you can't generate a meaningful SBOM or scan against a moving target:

```bash
cd crunch-tasks-api
pip freeze > requirements.txt
cat requirements.txt
```

You should see `flask==3.0.3` plus its transitive dependencies (`Werkzeug`, `Jinja2`, `MarkupSafe`, `click`, `itsdangerous`, `blinker`), each with an exact pinned version. This file — not the bare `pip install flask` command — is what you scan from here on.

## Task 2 — Generate the SBOM

```bash
pip-audit -r requirements.txt --format=cyclonedx-json -o sbom.json
```

Open `sbom.json` and find the `components` array. For each component, note the `name`, `version`, and `purl` (package URL) fields.

In `sbom-notes.md`, answer:

1. How many components does the SBOM list in total (direct **and** transitive)?
2. Pick one transitive dependency (something you never typed into a `pip install` command yourself) and name which direct dependency pulled it in.
3. What is the `purl` format, in general terms (`pkg:<ecosystem>/<name>@<version>`), and why is that more precise than just writing "Flask 3.0.3" in a spreadsheet cell?

## Task 3 — Scan for known vulnerabilities

```bash
pip-audit -r requirements.txt
```

Record the exact output in `sbom-notes.md`. If your installed `flask==3.0.3` and its dependencies come back clean (likely, since this is a current version), deliberately test the tool against an old, known-vulnerable pin so you see a real positive result:

```bash
echo "flask==0.12.2" > old-requirements.txt
pip-audit -r old-requirements.txt
```

Record this second output too — it should list at least one advisory ID (e.g., a `PYSEC-...` identifier) against Flask 0.12.2. This confirms `pip-audit` is actually checking against real advisory data, not just validating that a package exists.

## Task 4 — Design and build the findings schema

Create `dependency-findings-schema.sql`:

```sql
CREATE TABLE dependency_findings (
    id               INTEGER PRIMARY KEY,
    package_name     TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    advisory_id      TEXT NOT NULL,      -- e.g. 'PYSEC-2019-107'
    fix_versions     TEXT,               -- e.g. '1.0' or NULL if no fix yet
    severity         TEXT CHECK (severity IN ('low','medium','high','critical')),
    discovered_at    TEXT NOT NULL,      -- ISO 8601 timestamp
    status           TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','upgraded','accepted_risk','false_positive')),
    notes            TEXT
);
```

```bash
sqlite3 dependency-findings.db < dependency-findings-schema.sql
```

Notes on the design:

- `advisory_id` is `NOT NULL` — every row in this table exists *because* a scanner found a specific, named advisory; there's no "vague concern" row type here, unlike a general risk register.
- `fix_versions` is nullable because some advisories genuinely have no fix released yet — that's a real, valid state, not missing data.
- `severity` isn't something `pip-audit`'s default output gives you directly; you'll assign it yourself, using the advisory's CVSS score or your own judgment of exploitability and blast radius, exactly like every likelihood/impact score this course has had you justify since Week 1.

## Task 5 — Load your findings with Python

Write `load_dependency_findings.py`, using the **real** advisory IDs and versions from your Task 3 output against `old-requirements.txt` (illustrative shape below — your actual advisory IDs may differ):

```python
import sqlite3
from datetime import datetime, timezone

db = sqlite3.connect("dependency-findings.db")

findings = [
    {
        "package_name": "flask",
        "installed_version": "0.12.2",
        "advisory_id": "PYSEC-2019-107",
        "fix_versions": "1.0",
        "severity": "high",
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "status": "open",
        "notes": "Deliberately old pin used to prove pip-audit detects real advisories; not the version crunch-tasks-api actually runs.",
    },
]

for f in findings:
    db.execute(
        """
        INSERT INTO dependency_findings
            (package_name, installed_version, advisory_id, fix_versions,
             severity, discovered_at, status, notes)
        VALUES
            (:package_name, :installed_version, :advisory_id, :fix_versions,
             :severity, :discovered_at, :status, :notes)
        """,
        f,
    )

db.commit()
db.close()
print(f"loaded {len(findings)} dependency finding(s)")
```

```bash
python3 load_dependency_findings.py
```

## Task 6 — Query it

Run each of these and paste the output into `sbom-notes.md`:

```sql
-- 1. Everything still open, most severe first
SELECT package_name, installed_version, advisory_id, severity
FROM dependency_findings
WHERE status = 'open'
ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                        WHEN 'medium' THEN 2 ELSE 1 END DESC;

-- 2. Which findings have a fix already available?
SELECT package_name, installed_version, fix_versions
FROM dependency_findings
WHERE fix_versions IS NOT NULL AND status = 'open';

-- 3. Count of findings by severity
SELECT severity, COUNT(*) AS finding_count
FROM dependency_findings
GROUP BY severity;
```

## Expected result (spot checks)

- `sbom.json` lists at least 6 components (Flask plus its typical transitive dependency set).
- The scan against your **real** `requirements.txt` (current `flask==3.0.3`) should show few or no advisories — that's expected and good, not a failed exercise.
- The scan against `old-requirements.txt` (`flask==0.12.2`) shows at least one real advisory ID.
- Query 2 returns your Flask 0.12.2 row, since `fix_versions` is populated and `status` is `open`.

## Done when…

- [ ] `requirements.txt`, `sbom.json`, `dependency-findings-schema.sql`, `load_dependency_findings.py`, `dependency-findings.db`, and `sbom-notes.md` all exist.
- [ ] `sbom-notes.md` contains real output (not placeholder text) from both `pip-audit` runs (current and deliberately-old pins) and all three queries.
- [ ] You can explain, in one sentence, why the SBOM alone finds zero vulnerabilities and what the scan step adds on top of it.

## Stretch

- Regenerate the SBOM and re-scan after **upgrading** `old-requirements.txt` to a fixed version (`flask==1.0`) — confirm the advisory disappears from `pip-audit`'s output, then update that row's `status` to `'upgraded'` in the database rather than deleting it (a findings history you can query later — "what did we used to be vulnerable to" — is valuable; deleting rows throws that away).
- Add a `SELECT` that computes "days since discovered" for every still-open finding (`julianday('now') - julianday(discovered_at)`), the same kind of aging query a real vulnerability-management dashboard runs every morning.

## Submission

Commit `requirements.txt`, `sbom.json`, `dependency-findings-schema.sql`, `load_dependency_findings.py`, `dependency-findings.db`, and `sbom-notes.md` to your portfolio under `c50-week-09/exercise-03/`. This is the exact schema Challenge 1, Challenge 2, and the mini-project all extend — do not start over on a new schema later this week.
