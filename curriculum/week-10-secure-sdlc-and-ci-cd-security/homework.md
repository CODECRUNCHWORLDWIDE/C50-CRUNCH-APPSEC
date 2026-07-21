# Week 10 — Homework

Five problems, ~4 hours total, spread across the week. All hands-on work happens against your own local Crunch Deploy pipeline or small YAML/script snippets you write yourself — nothing here ever points at a real GitHub repository, cloud account, or third-party system.

---

## Problem 1 — Audit workflow snippets for pipeline flaws (45 min)

Below are five short, self-contained GitHub Actions snippets. For each, in `workflow-audit.md`, state: (a) which `PIPE-` category from this week's README it falls into, if any (missing gate, supply chain, leaked secret, over-privileged runner, or context-expression injection); (b) the exact fix; (c) if it's actually fine, name the specific reason (e.g., "already pinned to a SHA," "permissions already minimal").

```yaml
# Snippet A
- uses: actions/checkout@main

# Snippet B
- uses: actions/checkout@a12d2e6b9b8f9d1e0c3f4a5b6c7d8e9f0a1b2c3d

# Snippet C
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest

# Snippet D
- name: Notify
  run: curl -X POST https://hooks.example.test/notify -d "pr_title=${{ github.event.pull_request.title }}"

# Snippet E
- name: Run tests
  env:
    DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
  run: pytest --db-password="$DB_PASSWORD"
```

**Deliver** `workflow-audit.md` with all five judged correctly and justified.

---

## Problem 2 — Trace a supply-chain compromise, from Lecture 2's examples (45 min)

Lecture 2 described the SolarWinds and Codecov incidents in general terms. In `supply-chain-trace.md` (~300 words), pick **one** of the two and, using only publicly documented facts (do not fabricate technical detail you're not sure of — cite what you're confident about and say plainly where you're reasoning generally), answer: (a) at which SDLC phase did the tampering actually occur; (b) why would a code review of the affected *application's* source code have missed it entirely; (c) which specific hardening technique from this week (pinning, permissions, signing, gating) would have most directly prevented or detected it, and why.

---

## Problem 3 — Write a gate-tuning policy (45 min)

Crunch Deploy's SAST/SCA gates currently block on any `HIGH`/`CRITICAL` finding. In `gate-policy.md`, write a one-page policy covering: what severity blocks the build outright; what severity is logged but non-blocking; what the **accepted-risk exception** process looks like (who approves it, what it must contain, how long it's valid before it must be re-reviewed); and one worked example of a finding you'd accept as a time-boxed exception versus one you never would, with your reasoning for the difference.

---

## Problem 4 — Compare GPG signing to Sigstore/cosign (45 min)

Using Lecture 3 Section 7's comparison table as a starting point, write `signing-comparison.md` (~300 words) explaining, in your own words: what specifically makes cosign's approach "keyless," what a SLSA provenance attestation proves that a bare signature doesn't, and one concrete scenario where a long-lived GPG key (this week's lab technique) creates an operational risk that keyless signing avoids entirely.

---

## Problem 5 — Design a rollback plan (60 min)

This week's `deploy/deploy.sh` has no rollback mechanism — a bad deploy simply overwrites the previous one with no way back. In `rollback-plan.md` (~350 words):

1. Design a versioned deploy scheme for Crunch Deploy's local "prod" directory (e.g., timestamped or artifact-digest-named subdirectories, with a `current` symlink or pointer file) that would let you revert to the previous good deploy in one command.
2. Explain why a rollback plan belongs in the **Deploy** phase of the SDLC mapping from Lecture 1, not the **Operate** phase, even though you'd typically invoke it during an incident (an Operate-phase activity).
3. Tie your design back to artifact signing: if you kept the last 3 signed artifacts and their `signatures` rows, what query would tell you the most recent **verified** deploy before the current one — the one you'd roll back to?

**Deliver** `rollback-plan.md` with the design, the phase-placement justification, and the SQL query.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 45 min |
| 3 | 45 min |
| 4 | 45 min |
| 5 | 60 min |
| **Total** | **~4 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
