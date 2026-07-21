# Week 9 — Exercises

Three guided exercises, ~90 min each. Do them in order — Exercise 3 introduces the findings database this week's challenges and mini-project both extend. **Exercises 1–2 run entirely against `crunch-tasks-api` on `127.0.0.1`**, the app you built in the [week README](../README.md). Exercise 3 scans `crunch-tasks-api`'s own dependencies. Nothing here ever points at a system or a package registry you don't control.

1. **[Exercise 1 — Fix broken object-level authorization](exercise-01-fix-broken-object-authz.md)** — reproduce the BOLA on `GET /api/v1/tasks/<id>`, fix it, re-test.
2. **[Exercise 2 — Stop mass assignment](exercise-02-stop-mass-assignment.md)** — reproduce both mass-assignment flaws (registration and task update), fix both with explicit allowlists, re-test.
3. **[Exercise 3 — Generate and scan an SBOM](exercise-03-generate-and-scan-an-sbom.md)** — generate a CycloneDX SBOM for `crunch-tasks-api`'s dependencies, scan it with `pip-audit`, and load the findings into a SQLite database.

## Before you start

- You've read all three lectures and built `crunch-tasks-api` from the week README — `python3 app.py` starts cleanly and the login sanity check returns Alice's token.
- Python 3.10+ and `sqlite3` are working.
- `pip install pip-audit` for Exercise 3.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, risk scores, telemetry, logs, dependency scan results — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** This week's `dependency_findings` table (Exercise 3) gets the same treatment as every findings table since Week 1.

## Suggested workflow

- Keep one working directory per week, e.g. `c50-week-09/`, with `crunch-tasks-api/` inside it.
- Every demonstration is a `curl` command with an `Authorization: Bearer <token>` header — no cookie jars this week, just save the two lab tokens (`tok_alice_LABONLY_0001`, `tok_bob_LABONLY_0002`) somewhere you can copy-paste from.
- Save every `curl` command and its actual output as you go — "evidence" means the real request/response, not a description of one.
- If a fix breaks the *legitimate* case (Bob, the actual admin, or Alice updating her own task), that's not a smaller bug than the one you were fixing — always re-test both directions.
