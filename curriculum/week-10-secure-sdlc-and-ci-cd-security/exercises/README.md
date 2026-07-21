# Week 10 — Exercises

Three guided exercises, ~1–1.5h each. All three work against **your own** Crunch Deploy pipeline, run entirely on your own machine via `act` — the project you set up in the [week README](../README.md). Nothing you do this week touches a real GitHub repository, a real cloud account, or a real production system.

1. **[Exercise 1 — Add a build-failing security gate](exercise-01-add-a-failing-security-gate.md)** — wire Semgrep and Trivy into the pipeline as gates, prove `PIPE-1` (no gates at all) by watching them fail against the seeded app-level and dependency findings, then fix those findings until both gates pass clean.
2. **[Exercise 2 — Harden a runner](exercise-02-harden-a-runner.md)** — fix `PIPE-2` through `PIPE-5`: pin every third-party action to a commit SHA, add a least-privilege `permissions:` block, remove the hardcoded credential, and replace the unpinned `curl | bash` install with a checksum-verified one.
3. **[Exercise 3 — Sign and verify an artifact](exercise-03-sign-and-verify-an-artifact.md)** — fix `PIPE-6`: build a tarball, GPG-sign it, and gate the deploy step on a passing signature verification.

## Before you start

- Docker Desktop/Engine is running, and `act` runs successfully: `act -l` from inside `~/c50-week-10/crunch-deploy` should list the `build-and-deploy` job without error.
- The insecure baseline from the week README is committed locally: `git log --oneline` shows at least the `"Crunch Deploy: insecure baseline"` commit.
- You've read Lectures 1–3, or at minimum the lecture the exercise you're starting references.
- You have a `pipeline.db` SQLite database ready — Exercise 1, Task 1 creates it; Exercises 2 and 3 extend it.

## The schema you'll build across this week's exercises

Every exercise this week writes to the same growing database, so pipeline posture accumulates into one queryable record instead of scattered notes:

```sql
CREATE TABLE phases (
    id       INTEGER PRIMARY KEY,
    phase    TEXT NOT NULL
                CHECK (phase IN
                  ('requirements','design','build','test','deploy','operate')),
    activity TEXT NOT NULL,
    control  TEXT NOT NULL,
    owner    TEXT NOT NULL,
    notes    TEXT
);

CREATE TABLE gate_runs (
    id             INTEGER PRIMARY KEY,
    run_id         TEXT NOT NULL,
    gate           TEXT NOT NULL CHECK (gate IN ('sast','sca','secret_scan','signing')),
    tool           TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('pass','fail')),
    findings_count INTEGER NOT NULL DEFAULT 0,
    run_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY,
    gate_run_id INTEGER NOT NULL REFERENCES gate_runs(id),
    severity    TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    location    TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','fixed','accepted_risk'))
);

CREATE TABLE signatures (
    id          INTEGER PRIMARY KEY,
    artifact    TEXT NOT NULL,
    digest      TEXT NOT NULL,
    signed_by   TEXT NOT NULL,
    verified    INTEGER NOT NULL,
    verified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

`phases` records where each security activity lives in the SDLC (Lecture 1). `gate_runs` and `findings` record what your automated gates caught, and whether it's still open. `signatures` records every signing and verification event. By Sunday, `SELECT * FROM gate_runs WHERE status = 'fail'` should show your pipeline's real history of catching things — not zero rows (a gate that never once failed during development probably never ran for real), but zero **open** findings by the time the mini-project ships.

## Suggested workflow

- Break first, gate second, fix third — run the insecure baseline once (as the README has you do) so you've actually seen `PIPE-1` through `PIPE-6` do nothing to stop a bad build, before you close any of them.
- `act` re-pulls its runner image only once; after that, iterating on the workflow file is fast. Use `act push -P ubuntu-latest=catthehacker/ubuntu:act-latest` after every YAML edit.
- Diff your hardened `deploy.yml` against the insecure baseline before moving on to the next exercise — know exactly what changed and why, the same discipline every prior week's exercises have used.
