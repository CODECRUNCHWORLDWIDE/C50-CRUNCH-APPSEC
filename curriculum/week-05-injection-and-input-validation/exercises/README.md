# Week 5 — Exercises

Three guided exercises, ~1–1.5h each. All three work against **your own** Crunch Notes instance, running on `127.0.0.1` only — the app you set up in the [week README](../README.md). Every payload you type this week is aimed at a database and a shell you own.

1. **[Exercise 1 — Exploit then parameterize](exercise-01-exploit-then-parameterize.md)** — break VULN #1 and #2's SQL injection, then rewrite both as parameterized queries and prove the fix.
2. **[Exercise 2 — Build allowlist input validation](exercise-02-build-input-validation.md)** — fix VULN #4's OS command injection with allowlist validation, not a blocklist.
3. **[Exercise 3 — Fix a stored XSS](exercise-03-fix-stored-xss.md)** — exploit and fix VULN #3's stored XSS; stretch goal covers VULN #2 and #7.

## Before you start

- Crunch Notes is running: `python app.py`, confirm `http://127.0.0.1:5000/` loads and lists 8 links.
- You've read Lectures 1–3 (or at minimum, the lecture the exercise you're starting references).
- You have `curl` or `requests` (`pip install requests`) available for scripted payloads — clicking through a browser works for exploring, but recording evidence needs something repeatable.
- You have a `findings.db` SQLite database ready — Exercise 1, Task 1 creates it; Exercises 2 and 3 extend it.

## The findings/payload schema you'll build in Exercise 1

Every exercise this week writes to the same three tables, so results accumulate into one queryable record instead of scattered notes files:

```sql
CREATE TABLE findings (
    id           INTEGER PRIMARY KEY,
    vuln_id      TEXT NOT NULL,          -- e.g. 'VULN-1'
    route        TEXT NOT NULL,          -- e.g. '/login'
    category     TEXT NOT NULL,          -- 'sqli' | 'cmdi' | 'xss'
    description  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',   -- 'open' | 'fixed'
    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE payload_library (
    id          INTEGER PRIMARY KEY,
    category    TEXT NOT NULL,           -- 'sqli' | 'cmdi' | 'xss'
    payload     TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE verifications (
    id           INTEGER PRIMARY KEY,
    finding_id   INTEGER NOT NULL REFERENCES findings(id),
    payload_id   INTEGER NOT NULL REFERENCES payload_library(id),
    result       TEXT NOT NULL,          -- 'blocked' | 'allowed'
    tested_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes        TEXT
);
```

`findings` records what's broken. `payload_library` is your reusable attack collection — never a spreadsheet, always this table. `verifications` is the proof: one row per (finding, payload) pair, showing whether the fixed code blocked or allowed each attack. By Sunday, `SELECT * FROM verifications WHERE result = 'allowed'` should return **zero rows**.

## Suggested workflow

- Exploit first, fix second, verify third — don't skip straight to "I know the fix, I'll just write it." Seeing the bug work is what makes the fix stick.
- Use `requests` (or `curl`) for anything you'll re-run more than once — browser clicking is fine for the first "does this even work" check, but the verification step needs to be scriptable.
- Diff your fixed `app.py` against the original before moving on — know exactly what changed and why.
