# Exercise 3 — Capstone Hunt & Triage

**Goal:** Run SAST (Bandit), DAST (a probe script), SCA (`pip-audit`), and a manual review pass against your Exercise 2 build, land every finding in one `capstone_findings` table, and produce a single triaged, priority-ordered backlog.

**Estimated time:** 90 minutes.

## Setup

```bash
cd c50-week-12/crunch-ledger    # continue from Exercise 2, app.py already hardened
pip install bandit pip-audit requests
```

```sql
CREATE TABLE capstone_findings (
    finding_id    INTEGER PRIMARY KEY,
    source        TEXT NOT NULL CHECK (source IN ('sast','dast','sca','manual_review','threat_model')),
    tool_or_reviewer TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    location      TEXT NOT NULL,
    description   TEXT NOT NULL,
    linked_risk_id INTEGER,
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','fixed','retested_ok','wont_fix')),
    fix_description TEXT,
    retested_at    TEXT,
    notes          TEXT
);
```

## Task 1 — SAST with Bandit

```bash
bandit -r . -x ./venv -f json -o bandit-report.json
bandit -r . -x ./venv -ll
```

For every medium-or-higher finding, insert a row into `capstone_findings` with `source = 'sast'`. Expect at minimum the `debug=True` finding on `app.run(...)`. Decide its status (`wont_fix`, justified per Lecture 3 Section 3) and write the justification into `notes` now, not later.

## Task 2 — DAST with the probe script

Save Lecture 3 Section 4's `dast_probe.py`, extend it with **three more checks** covering the IDOR fix, the vertical-escalation fix, and the webhook signature fix (the lecture's version only covers the API auth, injection, and cookie-flag checks):

```python
def check_idor():
    r = requests.post(f"{BASE}/login", data={"username": "cl-erin", "password": "labpass1"})
    cookies = r.cookies
    r2 = requests.get(f"{BASE}/expenses/3", cookies=cookies)   # expense 3 belongs to cl-mona
    if r2.status_code == 200:
        log_finding("critical", "/expenses/<id>", "cl-erin could read another user's expense", "open")
    else:
        log_finding("critical", "/expenses/<id>", f"Correctly rejected cross-user access ({r2.status_code})", "retested_ok")


def check_vertical_escalation():
    r = requests.post(f"{BASE}/login", data={"username": "cl-erin", "password": "labpass1"})
    r2 = requests.post(f"{BASE}/admin/approve/1", cookies=r.cookies)
    if r2.status_code == 200:
        log_finding("critical", "/admin/approve/<id>", "employee could approve an expense", "open")
    else:
        log_finding("critical", "/admin/approve/<id>", f"Correctly rejected ({r2.status_code})", "retested_ok")


def check_webhook_timing_safety():
    # Not a true timing attack (impractical over localhost HTTP in a short script) --
    # this checks the SOURCE uses hmac.compare_digest, a proxy proof, not a live timing exploit.
    import inspect
    import app as app_module
    src = inspect.getsource(app_module.webhook_reimburse)
    if "compare_digest" in src:
        log_finding("high", "/webhook/reimburse", "Uses hmac.compare_digest -- constant-time", "retested_ok")
    else:
        log_finding("high", "/webhook/reimburse", "Still uses == for signature comparison", "open")
```

Run the full extended probe and confirm every check logs `retested_ok`:

```bash
python3 dast_probe.py
sqlite3 capstone_findings.db "SELECT source, severity, location, status FROM capstone_findings WHERE source = 'dast';"
```

## Task 3 — SCA with pip-audit

```bash
pip-audit -r requirements.txt --format json --output pip-audit-report.json
```

Insert one row per advisory found (ideally zero, if Exercise 2 Task 5 was done correctly). If the run is clean, insert a single `retested_ok` row documenting the clean scan, with today's date, so "we checked and it was clean" is itself a queryable fact.

## Task 4 — Manual review pass

Work through Lecture 3 Section 6's three checklist items against your current `app.py`, plus one of your own devising (reread every route once more, cold, as if you'd never seen it). For each observation — fixed or not — insert a `manual_review` row. At minimum you should log:

- The manager-approving-their-own-expense business-logic gap (whether or not you already fixed it in Exercise 2's stretch goal).
- Confirmation that `get_expense` returns a uniform `404`, not a distinguishing `403`, for both "doesn't exist" and "exists but not yours."
- One finding entirely of your own, from your own cold re-read.

## Task 5 — Triage query

```sql
SELECT source, severity, location, description, status
FROM capstone_findings
WHERE status = 'open'
ORDER BY
    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
    source;
```

Run it and read the output. This is your Challenge 1 backlog — in the order you'll actually close it.

## Done when…

- [ ] `capstone_findings` has rows from all four sources: `sast`, `dast`, `sca`, `manual_review`.
- [ ] Every one of the eleven original vulnerabilities has at least one `retested_ok` row proving it's closed, sourced from either the DAST probe or a manual check.
- [ ] At least one finding is genuinely new — not one of the eleven — found by the manual review pass or by Bandit.
- [ ] The Task 5 triage query runs cleanly and produces a sensible priority order (critical/open findings, if any remain, at the top).
- [ ] Every `wont_fix` status has a `notes` field written in Exercise 3, not deferred to "I'll explain it later."

## Stretch

- Add a fourth DAST check confirming the SQL-injection fix specifically returns the *same* result shape for a malicious and a benign search term (proof the query is now parameterized, not just that the malicious term "didn't work this time").
- Cross-reference `capstone_findings` against `risk_register` by `linked_risk_id` and write one query that shows, per original STRIDE row, whether it's now closed.

## Submission

Commit `bandit-report.json`, `dast_probe.py`, `pip-audit-report.json`, and `capstone_findings.db` to `c50-week-12/exercise-03/`. Challenge 1 closes everything this exercise's triage query still shows as open.
