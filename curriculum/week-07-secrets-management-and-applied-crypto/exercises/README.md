# Week 7 — Exercises

Three guided exercises. Do them in order — each builds on the lab you stood up in the README and depends on the work the previous exercise left behind. **Every exercise runs entirely inside `~/c50-week-07/leaky-crunch-vault`, on `127.0.0.1`.** Nothing here ever points at a system you don't own, and every secret in the lab is a fake, clearly-labeled placeholder — never enter a real credential anywhere in this week's files.

1. **[Exercise 1 — Scan and purge secrets](exercise-01-scan-and-purge-secrets.md)** — find every leaked secret (source, config, `.env`, logs, git history), log each as a row in SQLite, purge history, and rotate.
2. **[Exercise 2 — Encrypt data correctly](exercise-02-encrypt-data-correctly.md)** — replace `homemade_encrypt` (and the ECB/static-IV experiments) with authenticated encryption, keyed from a securely generated, properly stored key.
3. **[Exercise 3 — Sign and verify](exercise-03-sign-and-verify.md)** — fix the webhook's timing-unsafe comparison, then implement both HMAC and Ed25519 signing/verification.

## Before you start

- You've read all three lectures, and Crunch Vault (`app.py`, `config.py`, `crypto_experiments.py`) is running from the README's setup steps.
- `git log -p --all -- .env | grep -c "AKIA"` returns a nonzero count in `leaky-crunch-vault` — confirms your lab's leaked history is in place.
- `pip install flask cryptography` succeeded and `python -c "from cryptography.fernet import Fernet; print('ok')"` prints `ok`.

## Data tooling rule (every exercise, every week)

Any data this course stores or queries — findings, risk scores, telemetry, logs, **secret-scan results and remediation status** — goes in **SQLite (or PostgreSQL) via SQL, and/or Python**. **Never a spreadsheet.** This week that means a `secret_findings` table: every leaked secret you find is a row, and "fixed" means an `UPDATE` changed its `status`, not a memory of having handled it.

## Suggested workflow

- Keep all three exercises' work inside `~/c50-week-07/leaky-crunch-vault/` — you're editing one running lab all week, not standing up a new one per exercise.
- Create `week07.db` once, in Exercise 1, and keep extending the same `secret_findings` table through the mini-project — don't start a new database per exercise.
- Run `python app.py` in one terminal and keep it running; use a second terminal for `curl`, `git`, and your Python scripts.
- If a fix "feels done" but you haven't re-run the thing that found the original flaw (a scan, a repeated encryption, a repeated request) to confirm it's actually gone, it isn't done yet.
