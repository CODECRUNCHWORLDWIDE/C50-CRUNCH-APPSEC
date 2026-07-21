# Week 3 — Exercises

Three guided exercises, ~90 min each. Do them in order — Exercise 3 loads the evidence Exercises 1 and 2 produce. **Every exercise runs entirely against `crunch-notes` on `127.0.0.1`**, the app you built in the [week README](../README.md). Nothing here ever points at a system you don't own.

1. **[Exercise 1 — Demonstrate an access-control flaw](exercise-01-demonstrate-access-control-flaw.md)** — reproduce the IDOR and the missing role check yourself, capture evidence, fix both at the source, re-test.
2. **[Exercise 2 — Find a security misconfiguration](exercise-02-find-a-misconfiguration.md)** — trigger the debug leak, audit the missing headers, fix both, re-test.
3. **[Exercise 3 — Log findings to a database](exercise-03-log-findings-to-a-database.md)** — build a `findings` SQLite schema and load Exercises 1–2's results into it as queryable rows.

## Before you start

- You've read all three lectures and built `crunch-notes` from the week README — `python3 app.py` starts cleanly and `curl` against `/login` works.
- Your Week 1 lab is still available (`docker ps --filter network=appsec-lab` shows your containers) — not required for Exercises 1–2, but Exercise 3's queries reuse the same `findings` schema idea from Week 1.
- Python 3.10+ and `sqlite3` are working.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, risk scores, telemetry, logs — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** A `findings` table gives you a schema, constraints, and a query language a spreadsheet never will, and it's the exact discipline this week's mini-project and every findings report for the rest of this course depend on.

## Suggested workflow

- Keep one working directory per week, e.g. `c50-week-03/`, with `crunch-notes/` inside it.
- Keep separate cookie jars per user (`alice.txt`, `bob.txt`) — you'll reuse them across all three exercises.
- Save every `curl` command and its output as you go; "evidence" in Exercise 3 means the actual request/response, not a description of one.
- If a fix breaks the *legitimate* case (an admin who should still get in), that's not a smaller bug than the one you were fixing — always re-test both directions.
