# Exercise 1 — Add a Build-Failing Security Gate

**Goal:** Prove `PIPE-1` (no security gates at all) by wiring Semgrep (SAST) and Trivy (SCA + secret scan) into the pipeline, watch both fail against the app-level and dependency findings seeded in the README, then fix those findings until both gates pass clean.

**Estimated time:** 90 minutes.

## Before you start

Confirm the insecure baseline still runs:

```bash
cd ~/c50-week-10/crunch-deploy
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

You should see the tests pass and a `Deployed to ...` line, with no scanner step anywhere in the output — that absence is `PIPE-1`.

## Task 1 — Build your pipeline database

Save this as `setup_pipeline_db.py` and run it once:

```python
import sqlite3

conn = sqlite3.connect("pipeline.db")
conn.executescript("""
CREATE TABLE IF NOT EXISTS phases (
    id       INTEGER PRIMARY KEY,
    phase    TEXT NOT NULL CHECK (phase IN
                ('requirements','design','build','test','deploy','operate')),
    activity TEXT NOT NULL,
    control  TEXT NOT NULL,
    owner    TEXT NOT NULL,
    notes    TEXT
);
CREATE TABLE IF NOT EXISTS gate_runs (
    id             INTEGER PRIMARY KEY,
    run_id         TEXT NOT NULL,
    gate           TEXT NOT NULL CHECK (gate IN ('sast','sca','secret_scan','signing')),
    tool           TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('pass','fail')),
    findings_count INTEGER NOT NULL DEFAULT 0,
    run_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    gate_run_id INTEGER NOT NULL REFERENCES gate_runs(id),
    severity    TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    location    TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','fixed','accepted_risk'))
);
""")
conn.commit()
print("pipeline.db ready.")
```

Seed the `phases` table with at least these two rows before continuing — the full mapping is the mini-project's job, but this exercise's gates belong in the record now, while you're building them:

```python
import sqlite3
conn = sqlite3.connect("pipeline.db")
conn.executemany(
    "INSERT INTO phases (phase, activity, control, owner) VALUES (?, ?, ?, ?)",
    [
        ("build", "Static analysis on every change", "Semgrep gate, --error, blocks merge on finding", "whole team"),
        ("build", "Dependency + secret scanning on every change", "Trivy gate, --exit-code 1, HIGH/CRITICAL blocks merge", "whole team"),
    ],
)
conn.commit()
```

## Task 2 — Add the SAST gate and watch it fail

Edit `.github/workflows/deploy.yml`, adding a step **after** `pip install -r requirements.txt` and **before** the test step:

```yaml
      - name: SAST gate (Semgrep)
        run: |
          pip install semgrep
          semgrep --config=auto --error app.py
```

Run it:

```bash
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

Semgrep should report the `subprocess.run(..., shell=True, ...)` pattern in `/widgets/search` and the hardcoded `API_TOKEN` fallback, and the step should exit non-zero — the job fails, and the pipeline never reaches the deploy step. Record the gate run and its findings:

```python
import sqlite3
conn = sqlite3.connect("pipeline.db")
gr = conn.execute(
    "INSERT INTO gate_runs (run_id, gate, tool, status, findings_count) VALUES (?, ?, ?, ?, ?)",
    ("run-001", "sast", "semgrep", "fail", 2),
).lastrowid
conn.executemany(
    "INSERT INTO findings (gate_run_id, severity, rule_id, location, description) VALUES (?, ?, ?, ?, ?)",
    [
        (gr, "warning", "subprocess-shell-true", "app.py:/widgets/search", "shell=True with string-built command"),
        (gr, "warning", "hardcoded-secret", "app.py:API_TOKEN", "Hardcoded fallback token as a default value"),
    ],
)
conn.commit()
```

## Task 3 — Add the SCA + secret-scan gate and watch it fail

Add a second step, after the Semgrep step:

```yaml
      - name: SCA + secret-scan gate (Trivy)
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy fs --scanners vuln,secret --exit-code 1 --severity HIGH,CRITICAL .
```

Run `act` again. Trivy should report advisories against the pinned `PyYAML` and `requests` versions in `requirements.txt` — read the tool's own output for the current CVE IDs and severities rather than assuming any specific one; advisory databases update continuously, and this is the actual real-world workflow: the tool tells you, you don't memorize it in advance. Record the gate run the same way as Task 2 (`gate = "sca"`, `tool = "trivy"`).

## Task 4 — Fix the app-level findings

Edit `app.py`:

```python
# BEFORE
API_TOKEN = os.environ.get("CRUNCH_API_TOKEN", "widget-dev-token-please-change")

# AFTER -- no hardcoded fallback; fail loudly if the real secret isn't configured
API_TOKEN = os.environ["CRUNCH_API_TOKEN"] if "CRUNCH_API_TOKEN" in os.environ else None
```

```python
# BEFORE
result = subprocess.run(f"echo searching for {name}", shell=True, capture_output=True, text=True)

# AFTER -- list-form arguments, no shell, no string built from user input
result = subprocess.run(["echo", "searching for", name], capture_output=True, text=True)
```

## Task 5 — Fix the dependency findings

Bump the two flagged packages to current releases in `requirements.txt` (check the actual current, non-advisoried version with `pip index versions <package>` or PyPI directly — don't hardcode a version here that will itself be stale by the time you read this):

```
flask
PyYAML
requests
```

Reinstall and re-run:

```bash
pip install -U -r requirements.txt
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

## Task 6 — Verify: both gates pass, record it

Re-run both gates and confirm exit code `0` for each, then log the passing runs:

```python
import sqlite3
conn = sqlite3.connect("pipeline.db")
conn.executemany(
    "INSERT INTO gate_runs (run_id, gate, tool, status, findings_count) VALUES (?, ?, ?, ?, ?)",
    [("run-002", "sast", "semgrep", "pass", 0), ("run-002", "sca", "trivy", "pass", 0)],
)
conn.execute("UPDATE findings SET status = 'fixed' WHERE status = 'open'")
conn.commit()

for row in conn.execute("SELECT * FROM gate_runs ORDER BY run_at"):
    print(row)
```

## Expected result

- Two `gate_runs` rows with `status = 'fail'` from before the fix, and two more with `status = 'pass'` after.
- `SELECT * FROM findings WHERE status = 'open'` returns **zero rows**.
- `act push` now completes cleanly through both scanner steps and reaches `Deployed to ...` again.

## Done when…

- [ ] `.github/workflows/deploy.yml` has SAST and SCA/secret-scan steps that run **before** the test step, each capable of failing the job.
- [ ] `pipeline.db` shows the fail → fix → pass history for both gates, not just a final clean state.
- [ ] You can explain, without looking it up, the one flag on each tool that actually makes a finding stop the build (and what happens if you forget it).

## Stretch

- Add a `timeout-minutes: 10` at the job level now — you'll want it anyway once Exercise 2 removes the pipeline's other weaknesses, and it costs nothing to add early.
- Try running Semgrep without `--error` and Trivy without `--exit-code 1` against the still-broken app to see, concretely, that both tools happily print findings and still exit `0` — the exact "ran a scan" vs. "added a gate" distinction Lecture 3 draws.

## Submission

Commit `app.py`, `requirements.txt`, `.github/workflows/deploy.yml`, `pipeline.db`, and your setup/record scripts to your portfolio under `c50-week-10/exercise-01/`.
