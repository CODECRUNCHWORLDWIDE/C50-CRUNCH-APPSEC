# Week 6 — Exercises

Three guided exercises, ~90 min each. Do them in order — each builds on the `crunch-helpdesk` state the previous one left behind. **Every exercise runs entirely against your own local `crunch-helpdesk`, on `127.0.0.1`, inside your isolated `appsec-lab`.** Nothing here ever points at a system you don't own.

1. **[Exercise 1 — Exploit and fix an IDOR](exercise-01-exploit-and-fix-idor.md)** — demonstrate the cross-tenant and cross-user IDOR on `/tickets/<id>`, record it as evidence, fix it with an ownership-filtered query, re-test.
2. **[Exercise 2 — Implement RBAC](exercise-02-implement-rbac.md)** — build the role-permission matrix in SQLite, write the `@require_permission` decorator, and lock down every remaining route that's missing a function-level check.
3. **[Exercise 3 — Build an authz test matrix](exercise-03-authz-test-matrix.md)** — write a data-driven role × resource × action test suite and run it against every route, proving coverage instead of sampling it.

## Before you start

- You've read all three lectures, especially Lecture 3's deny-by-default section.
- `crunch-helpdesk` is set up per this week's [README](../README.md): `seed.py` has run, `app.py` is running on `127.0.0.1:5000`, and the sanity-check login for `cc-alice` returns `200`.
- You have `curl` (or an HTTP client of your choice) and `sqlite3` available.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, test results, telemetry — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** This week's `authz_findings` table (Exercise 1) and `authz_test_results` table (Exercise 3) are the concrete instances of that rule for access-control work specifically — both give you real, repeatable queries ("what's still open," "which role × resource pairs fail") that a spreadsheet cannot.

## Suggested workflow

- Work in a fresh directory per week, e.g. `c50-week-06/`, with `crunch-helpdesk/` as a subdirectory each exercise edits in place.
- Keep two or three terminal-saved cookie jars around (`cc-alice.txt`, `cc-dave.txt`, `al-erin.txt`) — you'll re-log-in as different roles and different companies constantly this week.
- Commit `app.py` after **every** exercise, not just at the end — you want a clean diff showing exactly what each exercise's fix changed.
- If a request you expected to fail with `403` instead returns `200`, stop and read the route before moving on — that's usually the actual lesson, not a bug in your test.
