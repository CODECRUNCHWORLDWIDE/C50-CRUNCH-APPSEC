# Week 1 — Exercises

Three guided exercises, ~90 min each. Do them in order — each depends on the lab and data the previous one built. **Every exercise runs entirely inside the isolated lab from Lecture 3.** Nothing here ever points at a system you don't own.

1. **[Exercise 1 — Provision the isolated lab](exercise-01-provision-the-isolated-lab.md)** — stand up the Docker lab network and three vulnerable targets; verify isolation before touching anything else.
2. **[Exercise 2 — Map an attack surface](exercise-02-map-an-attack-surface.md)** — inventory Juice Shop's entry points and trust boundaries into a SQLite findings store.
3. **[Exercise 3 — Build a risk register](exercise-03-build-a-risk-register.md)** — score your findings by likelihood × impact in SQLite and query it for "what do I fix first."

## Before you start

- You've read all three lectures, especially Lecture 3's isolation rules.
- Docker Desktop (or Engine) is installed and `docker run hello-world` works.
- Python 3.10+ is installed and `python3 -c "import sqlite3; print('ok')"` prints `ok`.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, risk scores, telemetry, logs — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** A spreadsheet has no schema, no constraints, no audit trail, and invites silent edits nobody can trace. A `findings` table gives you all of that for free, and it's the same discipline you'll use for real findings reports starting Week 3.

## Suggested workflow

- Do the exercises in a fresh directory per week, e.g. `c50-week-01/`.
- Keep your `lab-setup.sh` from Lecture 3 at the top of that directory — you'll re-run it often.
- Save every SQL script and Python file you write; you'll extend this same schema in later weeks.
- If a result surprises you, stop and figure out why before moving on — that's usually the actual lesson.
