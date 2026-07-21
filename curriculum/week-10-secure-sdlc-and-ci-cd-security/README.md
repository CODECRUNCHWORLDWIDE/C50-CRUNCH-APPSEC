# Week 10 — Secure SDLC & CI/CD Security

> **Goal:** by Sunday you can place the right security activity at every phase of the software lifecycle, wire automated scanners into a CI/CD pipeline as gates that actually fail the build, harden the pipeline itself against the specific ways attackers go after it, and sign a build artifact so the thing that gets deployed is provably the thing that passed every gate.

Welcome back to **C50 · Crunch AppSec**. Every week so far has made you better at finding and fixing a specific class of bug — injection, broken auth, bad access control, leaked secrets, missing scanners. This week is about the machine that turns your fixes into a running application: the software delivery pipeline itself. Two distinct but related ideas sit side by side this week. First, **security across the SDLC** — the discipline of putting the right security activity at the right phase (requirements, design, build, test, deploy, operate) instead of "we'll do a pentest before launch and call it security." Second, **security of the pipeline** — because the CI/CD system that builds, tests, and ships your code has become one of attackers' favorite targets in its own right: a compromised pipeline can poison every artifact it ever produces, and it usually holds more privilege (deploy keys, cloud credentials, signing keys) than the application it builds.

This week has a lab you'll recognize by shape from every prior week, even though the target is different: a small, deliberately **under-secured CI/CD pipeline** — a tiny Flask API called **Crunch Widgets**, built and "deployed" by a real GitHub Actions workflow file you own, run entirely on your own machine with [`act`](https://github.com/nektos/act) so nothing ever touches a real GitHub account, a real cloud provider, or a real production system. Six numbered pipeline flaws (`PIPE-1`–`PIPE-6`) are seeded into the workflow on purpose, mirroring Week 5's `VULN #` numbering — you'll close every one of them by Sunday, then reuse Week 8's own scanners (Semgrep, Trivy) as **build-failing gates** instead of one-off scans, and finish by signing the artifact those gates approved.

> **Ethics & legality — binding, every week.** Everything below runs **only** against a pipeline **you own**, on **your own machine**, using `act` to simulate GitHub-hosted runners locally in Docker containers with **no route to a real GitHub repository, real cloud account, or real production system**. The "deploy" step this week copies files into a local directory on your own disk that stands in for a production server — there is no real server anywhere in this lab. Challenge 2's pipeline-injection attack is exploited the same way every offensive technique in this course is: against your own local, isolated simulation, for the explicit purpose of learning to detect and close the exact hole a real attacker would use. Written authorization, defined scope, and the law govern every exercise this week and every week after it.

## Learning objectives

By the end of this week, you will be able to:

- **Place** the correct security activity at each SDLC phase — requirements, design, build, test, deploy, operate — and explain how each one reinforces the STRIDE threat model you built in Week 2.
- **Wire** Semgrep and Trivy (from Week 8) into a CI/CD pipeline as **gates**: steps whose non-zero exit code fails the build, not one-off scans you run and forget.
- **Harden** a CI/CD pipeline against its four biggest risk categories: poisoned/unpinned dependencies, leaked secrets, over-privileged runners, and shell-injection via untrusted context expressions.
- **Sign and verify** a build artifact so a tampered or unapproved artifact cannot reach the deploy step, and explain how this compares to the industry's keyless-signing (Sigstore/SLSA) approach.
- **Store** every gate result, finding, and signature-verification outcome as queryable rows in a SQL database — never a spreadsheet, never a Slack message nobody can query later.

## Prerequisites

- **Weeks 1–9 completed**, specifically: your isolated lab discipline (Week 1), STRIDE threat modeling (Week 2), Week 7's secrets-management habits, Week 8's Semgrep/Trivy tooling (this week reuses both directly — you are not learning new scanners, you're learning to make the ones you already know **block a build**), and Week 9's supply-chain vocabulary (dependency confusion, typosquatting — this week applies the same thinking to the pipeline's own third-party dependencies: GitHub Actions).
- Python 3.10+, `pip`, and `git`.
- **Docker Desktop or Docker Engine**, running — `act` uses it to simulate GitHub-hosted runners locally.
- Comfortable reading YAML and a shell script; you'll edit both all week.

## This week's target: the Crunch Deploy pipeline

Crunch Deploy is a tiny Flask service ("Crunch Widgets API") plus a real GitHub Actions workflow that builds, tests, and "deploys" it — entirely on your machine, via `act`, with **no GitHub account and no network egress required beyond the one-time tool installs below**.

```mermaid
flowchart LR
  dev["You: git commit\n(local repo only)"] --> act["act (local)\nsimulates GitHub-hosted runner\nin a Docker container"]
  act --> ci["Workflow: .github/workflows/deploy.yml\ncheckout -> install -> test -> deploy"]
  ci --> prod["deploy/deploy.sh\ncopies files to a LOCAL folder\nstanding in for 'prod'"]
```

### Set up Crunch Deploy (do this first)

**1. Install `act` and confirm Docker is running.**

```bash
# macOS
brew install act
docker --version   # confirm Docker Desktop/Engine is running
```

On Linux, download the release binary from the official releases page linked in `resources.md` rather than piping an install script into `bash` — Lecture 2 is about to explain, in detail, exactly why that pattern is a risk, so we don't practice it here even for our own tooling.

**2. Create the project.**

```bash
mkdir -p ~/c50-week-10/crunch-deploy && cd ~/c50-week-10/crunch-deploy
mkdir -p .github/workflows tests deploy
python3 -m venv venv && source venv/bin/activate
pip install flask pytest
```

**3. Save the application** as `app.py`:

```python
#!/usr/bin/env python3
"""Crunch Widgets API -- this week's CI/CD pipeline target.

This app is intentionally unremarkable. Most of this week's vulnerabilities
live in HOW it gets built and deployed (the pipeline), not in the app code --
though two small, deliberate app-level issues are seeded here so the SAST/SCA
gates you add in Exercise 1 have something real of their own to catch, in
addition to the pipeline-level flaws in deploy.yml below.
"""
import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

# GATE-BAIT (SAST): a hardcoded fallback "secret" -- Semgrep's
# generic-secrets / hardcoded-credentials rules should flag this. It is a
# SEPARATE mistake from PIPE-4 below (the pipeline's own leaked credential) --
# two independent flaws stacked on purpose, same discipline Week 5 used
# stacking plaintext passwords next to an unrelated injection bug.
API_TOKEN = os.environ.get("CRUNCH_API_TOKEN", "widget-dev-token-please-change")

WIDGETS = [
    {"id": 1, "name": "Sprocket", "qty": 42},
    {"id": 2, "name": "Gear", "qty": 17},
]


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/version")
def version():
    return jsonify(version="0.1.0")


@app.route("/widgets")
def widgets():
    return jsonify(widgets=WIDGETS)


@app.route("/widgets/search")
def search():
    # GATE-BAIT (SAST): shell=True with string-built input. Not exploitable
    # today because the fixed widget list above never reaches attacker input,
    # but a SAST rule correctly flags the PATTERN, not just today's reachable
    # data -- exactly Week 8's point that SAST reads code, not runtime input.
    name = request.args.get("name", "")
    result = subprocess.run(f"echo searching for {name}", shell=True, capture_output=True, text=True)
    return jsonify(query=name, note=result.stdout.strip())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050)
```

**4. Save `requirements.txt`** — two dependencies are pinned to old releases with publicly disclosed advisories on purpose, so Trivy's SCA gate (Exercise 1) has something real to catch. Run the tool and let it tell you the current advisory IDs and severities rather than memorizing any specific CVE number here — that's the actual SCA workflow, not a trivia exercise:

```
flask==3.0.0
PyYAML==5.3.1
requests==2.19.1
```

**5. Save `tests/test_app.py`**:

```python
from app import app


def test_healthz():
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_widgets():
    client = app.test_client()
    resp = client.get("/widgets")
    assert resp.status_code == 200
    assert len(resp.get_json()["widgets"]) == 2
```

**6. Save the INSECURE baseline workflow** as `.github/workflows/deploy.yml` — read every line, this is this week's "deliberately vulnerable app.py":

```yaml
name: Crunch Deploy CI

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python -m pytest tests/ -v
      - name: Deploy
        env:
          DEPLOY_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
        run: |
          curl -sSf https://example-ci-helper.test/install.sh | bash
          bash deploy/deploy.sh
```

**7. Save the local "deploy" script** as `deploy/deploy.sh`:

```bash
#!/usr/bin/env bash
# Simulated "production" deploy. Copies the app into a LOCAL folder standing
# in for a prod server -- there is no real server, no real network egress,
# and no real credential anywhere in this course. This is the lab-only
# stand-in so the pipeline has something concrete to "ship."
set -euo pipefail
PROD_DIR="${PROD_DIR:-$HOME/c50-week-10/crunch-deploy-prod}"
mkdir -p "$PROD_DIR"
cp -r app.py requirements.txt "$PROD_DIR"/
echo "Deployed to $PROD_DIR"
```

**8. Initialize a local-only git repo** (no remote, no push — `act` just needs a git context to resolve the event):

```bash
chmod +x deploy/deploy.sh
git init -q && git add -A && git commit -q -m "Crunch Deploy: insecure baseline"
```

**9. Confirm the pipeline runs** (the first run pulls a Docker image for the simulated runner — expect a multi-minute wait once):

```bash
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

You should see `checkout`, `setup-python`, the two tests passing, and a `Deployed to ...` line — the insecure pipeline runs clean, which is exactly the problem: nothing in it is watching for the six flaws seeded below.

### This week's six seeded pipeline flaws

You'll reference these numbers all week — write them down now, the same way Week 5 tracked `VULN #1`–`#7`:

| # | Where | Flaw | Category | Fixed in |
|---|-------|------|----------|----------|
| PIPE-1 | whole workflow | No SAST/SCA/secret-scan step at all — nothing fails the build on a real finding | Missing security gate | Exercise 1 |
| PIPE-2 | `uses: actions/checkout@v4`, `actions/setup-python@v5` | Third-party actions pinned to a **mutable tag**, not a commit SHA | Supply-chain / runner hardening | Exercise 2 |
| PIPE-3 | job/workflow level | No `permissions:` block → `GITHUB_TOKEN` defaults to broad read/write | Over-privileged runner | Exercise 2 |
| PIPE-4 | `env: DEPLOY_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE` | Credential hardcoded directly in the workflow source | Leaked secret | Exercise 2 |
| PIPE-5 | Deploy step, `curl ... \| bash` | Unpinned third-party script fetched over the network and executed with zero integrity check | Poisoned dependency | Exercise 2 |
| PIPE-6 | Deploy step | Whatever built successfully gets deployed as-is — no signature, no verification before shipping | Artifact integrity | Exercise 3 |

## This week's map

Work top to bottom. Each piece assumes the ones before it.

| # | File | What's inside | ~Time |
|--:|------|---------------|------:|
| 1 | [lecture-notes/01-security-across-the-sdlc.md](./lecture-notes/01-security-across-the-sdlc.md) | Which security activity belongs at each SDLC phase, and how each reinforces Week 2's threat model | 2h |
| 2 | [lecture-notes/02-hardening-the-ci-cd-pipeline.md](./lecture-notes/02-hardening-the-ci-cd-pipeline.md) | The pipeline as an attack surface: poisoned dependencies, leaked secrets, over-privileged runners, context-expression injection | 2h |
| 3 | [lecture-notes/03-security-gates-and-artifact-integrity.md](./lecture-notes/03-security-gates-and-artifact-integrity.md) | Wiring Semgrep/Trivy as build-failing gates without alert fatigue; signing and verifying artifacts | 2h |
| 4 | [exercises/exercise-01-add-a-failing-security-gate.md](./exercises/exercise-01-add-a-failing-security-gate.md) | Add SAST + SCA/secret-scan gates; prove PIPE-1 fails the build, then fix the app until it passes | 1.5h |
| 5 | [exercises/exercise-02-harden-a-runner.md](./exercises/exercise-02-harden-a-runner.md) | Fix PIPE-2 through PIPE-5: pin SHAs, least-privilege permissions, remove the hardcoded secret, kill the curl\|bash step | 1.5h |
| 6 | [exercises/exercise-03-sign-and-verify-an-artifact.md](./exercises/exercise-03-sign-and-verify-an-artifact.md) | Fix PIPE-6: GPG-sign the build artifact and gate deploy on a passing verification | 1h |
| 7 | [challenges/challenge-01-design-a-secure-pipeline.md](./challenges/challenge-01-design-a-secure-pipeline.md) | Design a secure pipeline for a new service from scratch, unassisted | 2h |
| 8 | [challenges/challenge-02-attack-and-defend-a-pipeline.md](./challenges/challenge-02-attack-and-defend-a-pipeline.md) | Exploit a context-expression shell-injection hole in your own local pipeline, then patch it and add a detector | 1.5h |
| 9 | [mini-project/README.md](./mini-project/README.md) | Rebuild Crunch Deploy end to end as a secure SDLC pipeline, with posture recorded in a database | 3h |
| 10 | [homework.md](./homework.md) | Extra practice, spread across the week | 4h |
| 11 | [quiz.md](./quiz.md) | 15 self-check questions + answer key | 1h |
| 12 | [resources.md](./resources.md) | Official docs + the few links worth your time | — |

## Weekly schedule

Adds up to roughly the course's full-time pace of **~28 hours**. Treat it as a target, not a stopwatch.

| Day | Focus | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Daily Total |
|-----------|------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|------------:|
| Monday | Security across the SDLC; set up Crunch Deploy | 2h | 0h | 0h | 0.5h | 1h | 0h | 3.5h |
| Tuesday | Hardening the pipeline; add failing gates | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Wednesday | Harden the runner: pin, scope, de-secret | 0h | 1.5h | 0h | 0.5h | 1h | 0h | 3h |
| Thursday | Gates + artifact integrity; sign and verify | 2h | 1h | 0h | 0.5h | 1h | 0.5h | 5h |
| Friday | Design challenge + attack/defend the pipeline | 0h | 0h | 3.5h | 0.5h | 1h | 0.5h | 5.5h |
| Saturday | Mini-project | 0h | 0h | 0h | 0h | 0h | 2h | 2h |
| Sunday | Quiz + review | 0h | 0h | 0h | 1h | 0h | 0h | 1h |
| **Total** | | **6h** | **4h** | **3.5h** | **3.5h** | **5h** | **3h** | **~28h** |

## By the end of this week you can…

- Point at any SDLC phase and name the specific security activity that belongs there, and explain what breaks down when that activity only happens at the end (a "pentest before launch" program).
- Read a CI/CD workflow file and name, from memory, its four biggest risk categories — and fix each one with the specific hardening technique this week taught, not a vague "lock it down."
- Turn a scanner you already know how to run (Semgrep, Trivy) into a build-failing gate with a sensible severity threshold, instead of a report nobody reads.
- Sign a build artifact, verify it before deploy, and explain — accurately — how that compares to Sigstore/cosign keyless signing and SLSA provenance.
- Query a database for exactly which gates passed, which failed, and which artifacts are verified, instead of trusting a green checkmark on faith.

## Up next

[Week 11 — Secure code review](../week-11-secure-code-review/) — you've now automated detection and hardened how software ships; next week trains the skill no scanner replaces: reading a pull request the way an attacker would, before it merges.

---

*Part of the Code Crunch Worldwide open curriculum · GPL-3.0 · If you find errors, please open an issue or PR.*
