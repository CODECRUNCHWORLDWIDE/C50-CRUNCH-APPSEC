# Mini-Project — SAST, DAST & SCA, Wired and Triaged into One Backlog

> Wire all three scanner classes against your lab target, triage the combined output — confirm true positives, dismiss false positives with justification — write one custom SAST rule, reconcile duplicates across tools, and ship a single risk-ranked findings backlog stored in a database. This is the week's capstone: proof you can run the automated hunt end to end, from raw scanner noise to a backlog an engineering team could actually work from.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

Every real AppSec tooling program answers the same question this project asks: three different scanners each found *something*, none of them agree on severity, some of their findings overlap, some are noise — what, specifically, should get fixed first, and why should anyone trust that ranking? This project has you produce a complete, defensible answer.

---

## Deliverable

A directory in your portfolio `c50-week-08/mini-project/` containing:

1. `pipeline.sh` — a single script that re-runs all three scans (Semgrep, ZAP, Trivy) against your lab target from a clean state.
2. `appsec.db` — your SQLite database, extended through this week's exercises and challenges, with a fully reconciled `findings` table.
3. `custom-rule.yaml` — your Challenge 1 rule (bring it forward; don't rebuild it).
4. `report.md` — a written summary tying it all together (structure specified below).

---

## Requirements

### Part 1 — The pipeline (verify, don't rebuild from scratch)

- `pipeline.sh` runs, in order: the Semgrep scan (Exercise 1) including your Challenge 1 custom rule alongside `--config=auto`, the ZAP baseline **and** authenticated full scan (Exercise 2), and the Trivy dependency scan (Exercise 3's setup) — all writing fresh output files.
- Confirm your Challenge 1 custom rule actually fires as part of this combined run, not just in isolation — `semgrep --config=auto --config=custom-rule.yaml ...` in one invocation.
- The script must be re-runnable from a clean checkout with no manual steps beyond having the lab up and the tools installed.

### Part 2 — Combined findings (extend Exercise 3 + Challenge 2)

- **At least 40 total findings** loaded across all three scanner categories, with **all three categories represented** (`sast`, `dast`, `sca`).
- **At least 20 findings triaged** to `confirmed` or `false_positive` — every `false_positive` row has real `triage_notes`; every `confirmed` row has `likelihood`, `impact`, and `risk_score` populated.
- **At least 2 reconciled duplicate clusters** (per Challenge 2) with `duplicate_of` set correctly, plus **at least 1 documented near-miss** you deliberately did not merge.
- Your custom rule from Challenge 1 has produced **at least one real finding** in this combined run, loaded into `findings` like any other.

### Part 3 — `report.md`

Write a short report covering:

1. **Executive summary** (~150 words) — as if handing this to an engineering manager: what was scanned, what tools were used, how many issues were found versus how many were confirmed real, and what the single highest-priority fix is.
2. **Top 10 backlog table** — pulled straight from your reconciled, ranked query (the `duplicate_of IS NULL` query from Challenge 2, extended to `LIMIT 10`), with `rule_id`/`title`, `severity_normal`, `risk_score`, and `status` columns.
3. **Scanner comparison** — a short table: findings per scanner category, and your best estimate of each scanner's false-positive rate among what you've triaged so far. State plainly which tool produced the most *actionable* signal for this specific app, in your judgment, and why.
4. **The custom rule, in context** — one paragraph on what your Challenge 1 rule caught that no generic ruleset would have, and where it landed in your final ranked backlog.
5. **Reflection** (~150 words): What was hardest — running the tools, or triaging honestly? Where did you catch yourself wanting to mark something "confirmed" or "false positive" without real evidence, just to move faster?

---

## Milestones

- **Milestone 1 (45 min):** `pipeline.sh` runs cleanly end to end, all three scanners' fresh output files exist, including your custom rule firing as part of the combined Semgrep run.
- **Milestone 2 (75 min):** Load everything into `appsec.db`; hit the 40-finding, 20-triaged minimums; reconcile at least 2 duplicate clusters plus 1 near-miss.
- **Milestone 3 (30 min):** Run the final ranked query, extract the top 10, and draft the scanner-comparison table.
- **Milestone 4 (30 min):** Write `report.md` end to end and proofread the executive summary as if a non-security engineering manager will read it first.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Pipeline correctness | 15% | `pipeline.sh` re-runs cleanly from scratch; custom rule fires as part of the combined scan, not just in isolation |
| Triage rigor | 30% | 20+ findings triaged, every dismissal has real written justification, every confirmed finding has a defensible risk score |
| Reconciliation | 20% | 2+ genuine duplicate clusters merged correctly, 1+ near-miss correctly kept separate, both with clear reasoning |
| Custom rule integration | 15% | Rule fires for real in the combined pipeline and is traceable in the final backlog, not just demonstrated in isolation back in Challenge 1 |
| Report clarity | 20% | Executive summary is readable by a non-security manager; top-10 table pulled from a real, correct query; scanner comparison is honest, not hand-wavy |

---

## Why this matters

This is the smallest complete loop of an automated AppSec tooling program: scan, load, triage, reconcile, rank, report. Every later week of this course builds on the discipline this project drills — Week 9 adds API-specific and supply-chain-specific scanning to the same pipeline shape, Week 10 puts these exact scanners into a CI/CD gate that runs on every commit, and Week 11's secure code review is the manual skill that automated tooling narrows your attention *toward*, never replaces. Keep `appsec.db` and `pipeline.sh` — you'll extend both, not rebuild them, for the rest of this course.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 9 — API security & software supply-chain security](../../week-09-api-and-supply-chain-security/).
