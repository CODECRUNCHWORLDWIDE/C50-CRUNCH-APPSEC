# Week 11 — Exercises

Three guided exercises, ~90 min each, all against the same PR: `crunch-invoices`'s `PR #482` from the [week README](../README.md). **Read before you run.** The whole point of this week is that a review starts with the source, not with an exploit attempt — resist the urge to jump straight to `curl`.

1. **[Exercise 1 — Review a PR for injection & authz](exercise-01-review-for-injection-and-authz.md)** — cold-read the diff, flag your suspicions, then confirm each one against the running app.
2. **[Exercise 2 — Taint-trace a flaw by hand](exercise-02-taint-trace-a-flaw.md)** — full hop-by-hop traces, source to sink, for the injection and the authorization gap.
3. **[Exercise 3 — Write a findings report](exercise-03-write-a-findings-report.md)** — turn Exercise 1's suspicions into full findings, stored and queried in `review_findings.db`.

## Before you start

- You've completed all three lectures.
- `crunch-invoices`'s baseline is set up and seeded (`python3 seed.py` ran clean, `python3 app.py` is running on `127.0.0.1:5050`).
- You have `pr-482.diff` saved from the week README, **not yet applied**.
- `sqlite3` is available (ships with Python).

## Suggested workflow

- Do these three in order — Exercise 2 traces flaws Exercise 1 already flagged, and Exercise 3 writes up findings Exercise 2 already traced. Skipping ahead means redoing work.
- Keep every raw note, trace, and finding in files — you're building the artifacts the mini-project assembles into one report.
- When you confirm a flaw against the running app, save the actual `curl` output. "It worked" is not evidence; the real response body is.
