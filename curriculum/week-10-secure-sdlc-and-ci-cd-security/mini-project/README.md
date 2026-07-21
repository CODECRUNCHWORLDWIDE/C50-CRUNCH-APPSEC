# Mini-Project — Rebuild Crunch Deploy as a Secure SDLC Pipeline

> Take Crunch Deploy from six deliberate pipeline flaws (plus Challenge 2's context-injection hole) to zero: map security activities across every SDLC phase, wire build-failing SAST/SCA/secret-scan gates, harden the runner to least privilege, sign and verify the deployed artifact — and record every gate outcome and the pipeline's full security posture in a database, not a slide deck.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

This is the week's capstone: the complete loop from "here's an under-secured pipeline" to "here's proof it's secure now, and here's the queryable record," using nothing but the tools this week taught — least-privilege permissions, pinned dependencies, build-failing scanners, signed artifacts, and a SQLite-backed posture database instead of a wiki page or a gut feeling.

---

## Deliverable

A directory in your portfolio `c50-week-10/mini-project/` containing:

1. `crunch-deploy/` — the fully hardened project: `app.py`, `requirements.txt`, `tests/`, `.github/workflows/deploy.yml`, `.github/workflows/issue-triage.yml`, `deploy/deploy.sh`.
2. `pipeline.db` — your SQLite posture database: `phases`, `gate_runs`, `findings`, and `signatures` tables, fully populated.
3. `run_full_pipeline_check.py` — a single script that re-runs every gate (SAST, SCA/secret-scan, context-injection detector, signature verification) and writes fresh `gate_runs`/`findings` rows reflecting the current state.
4. `report.md` — a written summary tying it all together (structure below).

---

## Requirements

### Part 1 — Every SDLC phase mapped (extend Lecture 1's table)

`phases` must have **at least one row per phase** (requirements, design, build, test, deploy, operate) for Crunch Deploy specifically — not generic textbook restatements. At minimum:

- **Requirements** — the abuse case(s) this pipeline is now provably defending against (tie explicitly to at least one `PIPE-` flaw).
- **Design** — the trust boundary the pipeline itself represents (who/what can trigger a run, what it's allowed to touch).
- **Build** — the SAST/SCA/secret-scan gates from Exercise 1.
- **Test** — what "passing" means now that gates exist (a green build implies more than it used to).
- **Deploy** — the signing/verification gate from Exercise 3.
- **Operate** — the context-injection detector from Challenge 2, framed as an ongoing monitoring control, not a one-time fix.

### Part 2 — Every flaw closed (verify, don't redo from scratch)

All six `PIPE` flaws from the week README, plus Challenge 2's context-injection hole, must be fixed in the final pipeline:

- `PIPE-1` — SAST (Semgrep) and SCA/secret-scan (Trivy) gates present, both build-failing, both currently passing.
- `PIPE-2` — every `uses:` pinned to a commit SHA, zero mutable tags anywhere in either workflow file.
- `PIPE-3` — an explicit, minimal `permissions:` block at the top of every workflow.
- `PIPE-4` — no hardcoded credential anywhere in the current tree; `PIPE-4-notes.md`-style reasoning about the git-history exposure carried over from Exercise 2.
- `PIPE-5` — no unpinned `curl | bash`/`sh` pattern anywhere; installs are pinned-version + checksum-verified.
- `PIPE-6` — artifact build → sign → verify → deploy, in that order, with a tampered-artifact test proving the verify step actually blocks a bad deploy.
- **Challenge 2's context-injection hole** — `issue-triage.yml` patched with `env:`-indirection, and `detect_context_injection.py` wired into `deploy.yml` as an additional gate.

### Part 3 — Full pipeline check sweep

- `run_full_pipeline_check.py` runs, in order: the SAST gate, the SCA/secret-scan gate, the context-injection detector, and a signature verification against the current artifact — recording a `gate_runs` row (and any `findings` rows) for each.
- **Zero rows** in `SELECT * FROM findings WHERE status = 'open'` at the end.
- At least one `gate_runs` row per gate type shows a **historical `fail`** (from before your fixes) alongside the current `pass` — the database should tell the story of what was caught, not just the final clean state.

### Part 4 — `report.md`

Write a short report covering:

1. **Executive summary** (~150 words) — as if handing this to a non-technical stakeholder: what kind of risk was this pipeline carrying, what did fixing it actually involve, and why should they trust it's secure now (not just "we tried").
2. **Before/after table** — one row per flaw (`PIPE-1`–`PIPE-6` plus the context-injection hole): where it lived, the one-sentence fix, and which gate now proves it stays fixed.
3. **One query that surprised you** — run something exploratory against `pipeline.db` (e.g., "which gate caught the most findings historically?", "how many distinct SDLC phases have at least one control tied to a gate that actually runs automatically, versus a manual/process control?") and report what you found.
4. **Reflection** (~150 words): which hardening category — pinning, permissions, secret hygiene, gating, or signing — took the most discipline to get right, and why? Where did you almost reach for a shortcut (a broad `permissions: write-all` "just to make it work," a suppressed finding without a written reason) before catching yourself?

---

## Milestones

- **Milestone 1 (45 min):** Confirm all fixes from Exercises 1–3 and Challenge 2 are present in one clean project; run the full pipeline by hand once and confirm a clean deploy.
- **Milestone 2 (45 min):** Populate `phases` fully across all six SDLC phases for Crunch Deploy specifically.
- **Milestone 3 (60 min):** Write and run `run_full_pipeline_check.py`; chase down and fix any lingering `open` finding until the sweep is clean.
- **Milestone 4 (30 min):** Write `report.md`, run the report queries, proofread the executive summary as if a non-technical reader sees it first.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| SDLC phase mapping | 20% | All six phases populated with Crunch-Deploy-specific activities, not generic restatements |
| Completeness of pipeline fixes | 30% | All six `PIPE` flaws plus the context-injection hole closed, using the structurally correct technique for each |
| Gate sweep & database | 25% | `run_full_pipeline_check.py` is real and runnable; database shows both historical failures and current passes; zero open findings |
| Report clarity | 25% | Executive summary readable by a non-technical stakeholder; before/after table is accurate and specific |

---

## Why this matters

This loop — map the activity to the phase, harden the mechanism, gate the build, sign the output, prove it against stored evidence — is the shape of a real secure software delivery program, not a classroom exercise you'll leave behind. The `pipeline.db` schema you built this week (`phases` → `gate_runs` → `findings` → `signatures`) is one you'll extend, not replace, straight through Week 11's secure code review and the Week 12 capstone, where the pipeline you hardened here is the one your capstone application actually ships through.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 11 — Secure code review](../../week-11-secure-code-review/).
