# Exercise 1 — Scan and Purge Secrets

**Goal:** Find every leaked secret in `leaky-crunch-vault` — in source, in the "removed" `.env`, and in the logs — record each as a row in a SQLite `secret_findings` table, purge the git history, rotate the credentials, and add a pre-commit scanner so it can't happen again.

**Estimated time:** 90 minutes.

## Before you start

Confirm the lab is in the state the README left it in:

```bash
cd ~/c50-week-07/leaky-crunch-vault
git log --oneline          # expect 3 commits
git log -p --all -- .env | grep -c AKIA   # expect a nonzero count
```

## Task 1 — Build the findings database

Create `week07_setup.sql` and run it with `sqlite3 week07.db < week07_setup.sql`:

```sql
CREATE TABLE IF NOT EXISTS secret_findings (
    id               INTEGER PRIMARY KEY,
    location         TEXT    NOT NULL,   -- e.g. 'config.py', '.env (git history)', 'app.log'
    secret_type      TEXT    NOT NULL,   -- e.g. 'aws_access_key', 'stripe_key', 'db_password'
    matched_snippet  TEXT    NOT NULL,   -- store a REDACTED preview, never the full secret
    commit_hash      TEXT,               -- NULL if not found in git history
    discovered_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           TEXT    NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'rotated', 'purged', 'false_positive')),
    remediated_at    TEXT
);
```

Note the `matched_snippet` column stores a **redacted** preview (e.g. `sk_live_51FA...GHIJ`, first 8 and last 4 characters) — the findings database itself must not become a second copy of the leak.

## Task 2 — Scan source and config with a regex sweep

Write `scan_secrets.py`:

```python
#!/usr/bin/env python3
import re
import sqlite3
from pathlib import Path

PATTERNS = {
    "generic_assignment": re.compile(
        r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"]([^'\"]{8,})['\"]"
    ),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "stripe_live_key": re.compile(r"sk_live_[0-9A-Za-z]{16,}"),
}

def redact(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "..." + value[-2:]
    return value[:8] + "..." + value[-4:]

def scan_working_tree(root: Path, db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    found = 0
    for path in root.rglob("*"):
        if path.is_dir() or ".git" in path.parts or path.name == "week07.db":
            continue
        try:
            text = path.read_text(errors="ignore")
        except (UnicodeDecodeError, PermissionError):
            continue
        for secret_type, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                snippet = match.group(0)
                conn.execute(
                    "INSERT INTO secret_findings (location, secret_type, matched_snippet) "
                    "VALUES (?, ?, ?)",
                    (str(path.relative_to(root)), secret_type, redact(snippet)),
                )
                found += 1
    conn.commit()
    conn.close()
    return found

if __name__ == "__main__":
    n = scan_working_tree(Path("."), "week07.db")
    print(f"Recorded {n} finding(s) in the working tree.")
```

Run it: `python scan_secrets.py`. You should see hits in `config.py` (API key, DB password) and, depending on log content, `app.log` if you've stored a test entry through the running app.

## Task 3 — Scan git history (the finding Task 2 misses)

The working-tree scan above cannot see `.env` — it was removed. Add a history sweep:

```bash
git log --all --diff-filter=A --name-only --format="COMMIT:%H" | grep -B1 "^\.env$"
```

That prints the commit hash that **added** `.env`. Confirm the leak and record it:

```python
import subprocess
import sqlite3

commit_hash = subprocess.run(
    ["git", "log", "--all", "--format=%H", "-1", "--", ".env"],
    capture_output=True, text=True
).stdout.strip()

content = subprocess.run(
    ["git", "show", f"{commit_hash}:.env"], capture_output=True, text=True
).stdout

conn = sqlite3.connect("week07.db")
conn.execute(
    "INSERT INTO secret_findings (location, secret_type, matched_snippet, commit_hash) "
    "VALUES (?, ?, ?, ?)",
    (".env (git history)", "aws_access_key", "AKIAIOSFODNN...MPLE", commit_hash),
)
conn.commit()
conn.close()
print(f"Confirmed .env leak at commit {commit_hash[:8]}")
```

## Task 4 — Query your own findings

```sql
SELECT secret_type, COUNT(*) AS n FROM secret_findings GROUP BY secret_type ORDER BY n DESC;
SELECT location, secret_type, status FROM secret_findings WHERE status = 'open';
```

## Task 5 — Rotate, then purge (in that order)

**Rotate first.** Any secret that was ever committed and could have been pushed is compromised regardless of whether you can still find it. In this lab, "rotating" means replacing the fake value with a fresh fake value and moving it out of source entirely:

```python
# config.py, after rotation -- values now come from the environment, not source
import os
API_KEY = os.environ["CRUNCH_VAULT_API_KEY"]
DB_PASSWORD = os.environ["CRUNCH_VAULT_DB_PASSWORD"]
FLASK_SECRET_KEY = os.environ["CRUNCH_VAULT_FLASK_SECRET"]
```

```bash
# .env for LOCAL DEV ONLY -- create it now, and put it in .gitignore BEFORE
# it's ever staged.
echo ".env" >> .gitignore
cat > .env <<'EOF'
CRUNCH_VAULT_API_KEY=sk_live_REDACTED-EXAMPLE-not-a-real-key
CRUNCH_VAULT_DB_PASSWORD=Vault_Admin_2024_ROTATED!
CRUNCH_VAULT_FLASK_SECRET=a-freshly-rotated-fake-secret
EOF
git add config.py .gitignore
git commit -q -m "Rotate secrets; load from environment instead of source"
```

**Then purge history.** `git filter-repo` (the tool git.scm's own docs now recommend over the older `filter-branch`) rewrites every commit that ever touched `.env`:

```bash
pip install git-filter-repo
git filter-repo --path .env --invert-paths --force
```

Verify the purge:

```bash
git log --all --oneline -- .env    # expect: no output at all now
```

## Task 6 — Prevent recurrence

Install a pre-commit secret scanner so this can't happen again silently:

```bash
pip install detect-secrets
detect-secrets scan > .secrets.baseline
git add .secrets.baseline
git commit -q -m "Add detect-secrets baseline"
```

## Task 7 — Update your findings' status

```sql
UPDATE secret_findings
SET status = 'rotated', remediated_at = CURRENT_TIMESTAMP
WHERE secret_type IN ('aws_access_key', 'stripe_live_key', 'db_password');

UPDATE secret_findings
SET status = 'purged', remediated_at = CURRENT_TIMESTAMP
WHERE location = '.env (git history)';
```

## Expected result (spot checks)

- `SELECT COUNT(*) FROM secret_findings;` returns at least 3 (config.py's key, config.py's password, the `.env` history finding).
- `git log --all --oneline -- .env` returns **nothing** after the purge.
- `python -c "import config"` no longer raises with a hardcoded value visible — it reads from `os.environ`, and fails clearly (`KeyError`) if the env var is unset, which is the correct failure mode (loud, not silent).
- `git diff HEAD~1 -- .gitignore` shows `.env` was added **before** any `.env` content could be staged going forward.

## Done when…

- [ ] `week07.db`'s `secret_findings` table has at least 3 rows, each with a **redacted** snippet, never the full value.
- [ ] `config.py` reads every secret from `os.environ`; no secret value appears in any tracked file.
- [ ] `git log --all --oneline -- .env` is empty — the history is purged, not just the working tree.
- [ ] `detect-secrets` (or gitleaks) is installed with a baseline committed, so a future accidental secret fails a scan instead of merging silently.
- [ ] Every row's `status` reflects what you actually did — `rotated`, `purged`, or still `open` if you haven't gotten to it.

## Stretch

- Run `gitleaks detect --source . -v` against the (now-purged) repo and compare its findings to your own `scan_secrets.py` — note anything it catches that your regex sweep missed.
- Write one query answering "how many days would this secret have been live and unrotated if I hadn't caught it this week?" using `discovered_at` and a hypothetical detection-lag assumption you state explicitly.

## Submission

Commit `week07_setup.sql`, `scan_secrets.py`, `week07.db`, and your rotated `config.py`/`.gitignore` to your portfolio under `c50-week-07/exercise-01/`. Keep `week07.db` — Exercises 2–3 and the mini-project extend the same database.
