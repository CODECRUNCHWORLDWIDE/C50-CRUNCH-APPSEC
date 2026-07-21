# Week 12 — Exercises

Three guided exercises, ~90–120 min each. Do them in order — each builds on the `crunch-ledger` state the previous one left behind. **Every exercise runs entirely against your own local Crunch Ledger, on `127.0.0.1`, inside your isolated capstone lab.** Nothing here ever points at a system you don't own.

1. **[Exercise 1 — Capstone threat model](exercise-01-capstone-threat-model.md)** — produce the written scope statement, the data-flow diagram, the full STRIDE table, and a queryable risk register for Crunch Ledger (or your own chosen target).
2. **[Exercise 2 — Capstone secure build](exercise-02-capstone-secure-build.md)** — implement all eleven fixes from Lecture 2, in priority order from Exercise 1's register, and re-test every one by hand.
3. **[Exercise 3 — Capstone hunt & triage](exercise-03-capstone-hunt-and-triage.md)** — run Bandit, the DAST probe script, `pip-audit`, and a manual review pass against your hardened build; merge every finding into one triaged database.

## Before you start

- You've read all three lectures, especially Lecture 1's scoping section if you're hardening your own app instead of Crunch Ledger.
- Crunch Ledger is set up per this week's [README](../README.md): `seed.py` has run, `app.py` starts cleanly on `127.0.0.1:5100`.
- You have `curl` (or an HTTP client of your choice), `sqlite3`, and a working virtualenv with `flask`, `cryptography`, `bandit`, and `pip-audit` installed.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, test results, risk registers, telemetry — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** This week's `risk_register` table (Exercise 1) and `capstone_findings` table (Exercise 3) are this week's concrete instances of that rule: real, repeatable queries ("what's still open," "what's `accepted` and why") that a spreadsheet cannot give you.

## Suggested workflow

- Work in a fresh directory, e.g. `c50-week-12/crunch-ledger/`, and commit after every exercise — a clean diff per exercise makes Challenge 1's re-test and the mini-project's evidence much easier to assemble later.
- Keep `SCOPE.md` (Exercise 1) at the root of your capstone repo — every later exercise and challenge assumes it exists and is accurate.
- Export `FLASK_SECRET_KEY` and `WEBHOOK_SIGNING_SECRET` in every terminal session before starting `app.py`, once Exercise 2's secrets fix is in place — a bare `python3 app.py` without them should fail loudly (`KeyError`), which is itself proof the fix is real.
- If a request you expected to fail with `401`/`403` instead returns `200`, stop and read the route before moving on — that's usually the actual lesson, not a bug in your test.
