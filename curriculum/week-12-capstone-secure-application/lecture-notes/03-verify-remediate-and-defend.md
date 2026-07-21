# Lecture 3 — Verify, Remediate & Defend

> **Duration:** ~2 hours. **Outcome:** You have run SAST, DAST, and SCA tooling plus a structured manual review against your hardened Crunch Ledger, merged every finding into one triaged database, closed the ones that remain, and prepared the evidence and rationale a design-review defense will actually be judged on.

> **Lab reminder.** Every scan and review below runs against **your own hardened Crunch Ledger**, on `127.0.0.1`, under the scope document from Lecture 1. The point of this lecture is proof, not more building — Lecture 2 already fixed the eleven known vulnerabilities; this lecture verifies that claim independently and looks for what Lecture 2 might have missed.

## 1. Why verify after you already fixed everything

It's tempting to treat Lecture 2's fixes as the finish line — you found eleven bugs, you fixed eleven bugs, done. Two things make that premature. First, **a fix you believe works and a fix you've proven works are not the same claim** — Week 8 built this exact discipline: findings live in a database, and "fixed" means a re-test recorded a pass, not a memory of having edited the file. Second, **the hunt in this lecture might find something Lecture 2 never touched** — a scanner and a human reviewer, working from a fresh eye, routinely surface issues the original build's mental model missed entirely, precisely because they aren't anchored to "the eleven things I already know about." Both reasons are why this lecture runs the tools **again**, on the fixed code, rather than treating Lecture 2's manual re-tests as sufficient.

## 2. The findings database — one table for every source

Consistent with every prior week's evidence discipline, every finding this week — whether it comes from a scanner, a manual review, or was already logged as a risk-register row in Lecture 1 — lands in one table, so "how many open findings are left" and "what did the DAST probe actually catch that the SAST scan didn't" are `SELECT`s, not memories.

```sql
CREATE TABLE capstone_findings (
    finding_id    INTEGER PRIMARY KEY,
    source        TEXT NOT NULL CHECK (source IN ('sast','dast','sca','manual_review','threat_model')),
    tool_or_reviewer TEXT NOT NULL,        -- 'bandit', 'dast_probe.py', 'pip-audit', or your own name
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    location      TEXT NOT NULL,           -- file:line, or route
    description   TEXT NOT NULL,
    linked_risk_id INTEGER,                -- FK to risk_register, if this finding maps to a Lecture 1 row
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','fixed','retested_ok','wont_fix')),
    fix_description TEXT,
    retested_at    TEXT,
    notes          TEXT
);
```

## 3. Running SAST — Bandit against the fixed code

Bandit's Python-specific static analysis catches a different slice of issues than the manual, class-by-class hunt Lecture 2 walked through — it's worth running even though you already know (and fixed) the eleven seeded bugs, because Bandit reasons about patterns, not about the specific story this app tells.

```bash
bandit -r . -x ./venv -f json -o bandit-report.json
bandit -r . -x ./venv -ll   # human-readable, medium+ severity only
```

Load every medium-or-higher finding into `capstone_findings` with `source = 'sast'`. Expect Bandit to flag `app.run(host="127.0.0.1", debug=True)` — Flask's debug mode exposes an interactive debugger console on unhandled exceptions, which is fine for a local lab but is exactly the kind of thing a SAST tool should flag regardless of context, because the tool can't know this host will never be anything but `127.0.0.1`. Log it, then decide: `wont_fix` (with a written justification — lab-only, never deployed) is a legitimate status here, and Challenge 2's defense review will ask you to justify that call out loud.

## 4. Running DAST — a probe script against the live app

Week 8 introduced DAST as testing the running application from the outside, the way an external caller would, rather than reading source. A small probe script, run against your live Crunch Ledger, closes the loop on whether Lecture 2's fixes actually changed the *observed* behavior, not just the source:

```python
#!/usr/bin/env python3
"""dast_probe.py -- runs a small set of black-box checks against a LIVE,
LOCAL Crunch Ledger on 127.0.0.1. Never point this at a host you don't own."""
import sqlite3
import requests

BASE = "http://127.0.0.1:5100"
findings_db = sqlite3.connect("capstone_findings.db")


def log_finding(severity, location, description, status="open"):
    findings_db.execute(
        "INSERT INTO capstone_findings (source, tool_or_reviewer, severity, location, description, status) "
        "VALUES ('dast', 'dast_probe.py', ?, ?, ?, ?)",
        (severity, location, description, status),
    )
    findings_db.commit()


def check_unauthenticated_api():
    r = requests.get(f"{BASE}/api/expenses")
    if r.status_code == 200:
        log_finding("critical", "/api/expenses", "Returned 200 with no auth -- still exposed", "open")
    else:
        log_finding("critical", "/api/expenses", f"Correctly rejected unauthenticated call ({r.status_code})", "retested_ok")


def check_injection_probe():
    r = requests.get(f"{BASE}/expenses/search", params={"q": "%' OR 1=1 --"})
    rows = r.json() if r.ok else []
    if isinstance(rows, list) and len(rows) >= 3:   # whole seeded table would return here if still injectable
        log_finding("critical", "/expenses/search", "Injection payload returned the full table", "open")
    else:
        log_finding("critical", "/expenses/search", "Injection payload returned no meaningful leak", "retested_ok")


def check_cookie_flags():
    r = requests.post(f"{BASE}/login", data={"username": "cl-erin", "password": "labpass1"})
    set_cookie = r.headers.get("Set-Cookie", "")
    missing = [flag for flag in ("HttpOnly", "SameSite") if flag not in set_cookie]
    if missing:
        log_finding("medium", "/login (Set-Cookie)", f"Missing flags: {missing}", "open")
    else:
        log_finding("medium", "/login (Set-Cookie)", "HttpOnly and SameSite both present", "retested_ok")


if __name__ == "__main__":
    check_unauthenticated_api()
    check_injection_probe()
    check_cookie_flags()
    print("DAST probe complete -- see capstone_findings.db")
```

This script is deliberately small — three checks, one per fixed vulnerability class — not a general-purpose scanner. Extend it yourself for Exercise 3 to cover the IDOR, the escalation routes, and the webhook signature check, so every one of Lecture 2's fixes has a corresponding automated, re-runnable proof rather than a one-time manual `curl`.

## 5. Running SCA — one more pass

Re-run `pip-audit` after Lecture 2's dependency bump, to prove the fix rather than assume it:

```bash
pip-audit -r requirements.txt --format json --output pip-audit-report.json
```

A clean run (no advisories) is itself the evidence — log a `capstone_findings` row with `status = 'retested_ok'` and the report's timestamp, so "we checked and it was clean on this date" is a fact in the database, not a claim in a README.

## 6. The manual review pass

Week 11 covered reading a diff for vulnerability classes a tool won't catch — business-logic flaws, subtle authorization gaps, and design decisions that are "technically not a bug" but are still wrong. Apply that same checklist to Crunch Ledger's **current, fixed** state, treating it as a diff against nothing (a fresh read), not against the vulnerable original:

- **Does every route that touches data check both authentication and authorization, explicitly, not by relying on `require_role` having been remembered?** Grep for every `@app.route` and confirm each either carries `@require_role` or has an explicit, commented reason it's intentionally open (a health check, for instance — Crunch Ledger has none, but note the pattern for your own future apps).
- **Does the approval flow have a logic gap the fixes didn't touch?** Nothing in Lecture 2 stops a manager from approving their **own** expense — the role check passed, but the ownership relationship between approver and submitter was never modeled. This is exactly the kind of business-logic flaw Week 11 named: not a CWE, not a scanner finding, a design gap a human has to notice. Log it as a `manual_review` finding, decide whether it's in scope to fix this week (Challenge 1 asks you to), and write down your reasoning either way.
- **Is there a code path that returns different errors for "not found" versus "found but forbidden"** (Week 6's information-disclosure lesson)? Check `get_expense`'s current fixed form — confirm it returns a uniform `404` in both cases, not a `403` that would leak existence.

Log every manual-review observation, fixed or not, as its own `capstone_findings` row with `source = 'manual_review'` — a review that only produces prose is a review whose conclusions can't be queried, prioritized, or proven complete later.

## 7. Triage — merging everything into one priority order

With SAST, DAST, SCA, manual review, and the Lecture 1 risk register all landed in the same schema, triage is a query, not a meeting:

```sql
SELECT source, severity, location, description, status
FROM capstone_findings
WHERE status = 'open'
ORDER BY
    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
    source;
```

The manager-approving-their-own-expense finding from Section 6 and the debug-mode Bandit finding from Section 3 are both real — but they don't carry equal weight, and the query above puts them in the order that reflects that, automatically, every time you re-run it as new findings land.

## 8. Preparing the defense

Challenge 2's design-defense review will ask you, cold, to justify decisions you made days earlier. Prepare for it now, while the reasoning is fresh, by writing (not just thinking) answers to four questions for **every** `wont_fix` or `accepted` status in your findings database and risk register:

1. What is the specific risk being accepted?
2. What is the likelihood and impact, and why did you rate them that way?
3. What compensating control, if any, reduces the risk even though the underlying issue isn't fixed?
4. What would have to change (in the app, in its deployment, in its user base) for this decision to need revisiting?

A `wont_fix` on Flask's debug mode is easy to defend (Question 4's answer is simply "if this ever runs anywhere but 127.0.0.1"). A `wont_fix` on the manager-approving-their-own-expense business-logic gap is harder to defend and might not survive the exercise of writing it down — which is exactly the value of doing this now rather than answering off the cuff in Challenge 2.

## 9. Check yourself

- Why does this lecture re-run tools against code you already fixed by hand, instead of trusting Lecture 2's manual re-tests?
- What did the manual review pass find that no SAST, DAST, or SCA tool could have — and why couldn't a tool have found it?
- Why is `wont_fix` with a written justification a legitimate outcome for a findings database, rather than something to avoid at all costs?
- If your DAST probe script and your manual `curl` re-test from Lecture 2 disagree about whether a fix holds, which do you trust more, and why?
- Write, right now, your answer to Section 8's four questions for one `accepted` or `wont_fix` row in your own register. Would it survive being read aloud to a stranger?

If those are automatic, Exercise 3 has you build out this full hunt-and-triage pipeline against your own Crunch Ledger checkout, and Challenge 1 has you close every finding this lecture's queries surface, re-tested and proven. Challenge 2 is the design-defense review itself — the four-question exercise from Section 8, for real, under questioning.

## Further reading

- **OWASP DAST guidance (Web Security Testing Guide):** <https://owasp.org/www-project-web-security-testing-guide/>
- **Bandit documentation:** <https://bandit.readthedocs.io/>
- **OWASP Vulnerability Management Guide:** <https://owasp.org/www-project-vulnerability-management-guide/>
- **NIST SP 800-30 — Guide for Conducting Risk Assessments:** <https://csrc.nist.gov/pubs/sp/800/30/r1/final>
