# Week 8 — Exercises

Three guided exercises, ~90 min each. Do them in order — Exercise 3 loads the actual output files Exercises 1 and 2 produce. **Static analysis runs against your own lab target's published source; dynamic analysis runs only inside the `appsec-lab` Docker network.** Nothing here ever points at a system you don't own.

1. **[Exercise 1 — Run a SAST scan](exercise-01-run-a-sast-scan.md)** — run Semgrep against Juice Shop's source, then hand-triage five real findings yourself before trusting any tool's verdict.
2. **[Exercise 2 — Run a DAST scan](exercise-02-run-a-dast-scan.md)** — run a ZAP baseline scan, then an authenticated scan, against your running lab.
3. **[Exercise 3 — Triage into a database](exercise-03-triage-into-a-database.md)** — load all three scanners' output into `appsec.db`, normalize severities across tools, and query the combined backlog.

## Before you start

- Your Week 1 lab (`appsec-lab` network, Juice Shop container) is up: `docker network ls` shows `appsec-lab`, and `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000` prints `200`.
- Your `appsec.db` from Weeks 1–7 exists and has at least the `targets` table populated.
- `semgrep`, `docker`, and `trivy` are installed (`semgrep --version`, `docker --version`, `trivy --version` all print something).

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, risk scores, telemetry, logs — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** This week is the sharpest test of that rule yet: three tools, three output formats, one schema. A spreadsheet with three tabs and manual copy-paste is exactly the failure mode this rule exists to prevent — no enforced schema, no query, no audit trail for who dismissed what and why.

## Suggested workflow

- Work in `c50-week-08/` at your portfolio root, with subdirectories `exercise-01/`, `exercise-02/`, `exercise-03/`.
- Keep every raw scanner output file (`semgrep-results.json`, `baseline-report.json`, `full-report.json`, `trivy-results.json`) — Exercise 3 loads all of them, and the mini-project re-uses them again.
- If a scanner's finding count surprises you (too many, too few, zero), stop and figure out why before moving on — a silent misconfiguration (wrong target URL, scan aborted early, ruleset not actually loaded) is a more common cause than "the app is just that clean."
