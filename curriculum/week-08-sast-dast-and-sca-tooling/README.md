# Week 8 — SAST, DAST & SCA Tooling

> **Goal:** by Sunday you can run three different classes of open-source security scanner against your own lab targets, explain precisely what each one can and cannot see, write a custom static-analysis rule for a pattern generic rulesets miss, and — the hard part — turn three noisy tool outputs into one deduplicated, risk-ranked backlog stored in a database, with every dismissal justified in writing.

Welcome back to **C50 · Crunch AppSec**. Weeks 3–7 taught you to find and fix vulnerability classes by hand — reading code, poking at auth, tracing an injection. That doesn't scale past a handful of files. This week is about **automating the hunt**: static analysis (SAST) reads source code without running it; dynamic analysis (DAST) probes a running application without seeing its source; software composition analysis (SCA) checks whether the *libraries* you depend on carry known vulnerabilities. Each one sees a different slice of the problem, and each one is blind to what the others catch — which is exactly why real programs run all three, not one.

The genuinely hard skill this week isn't running the tools — `semgrep --config=auto` is one command. It's **triage**: scanners are trained to over-report, because a missed vulnerability is worse than a noisy one. A raw scan of Juice Shop will hand you dozens of "findings," and a meaningful fraction are false positives, duplicates across tools, or real-but-unreachable code paths. Turning that pile into a backlog someone can actually work from — confirmed, deduplicated, ranked by risk, with a paper trail for every dismissal — is the actual job of an AppSec engineer running these tools day to day.

> **Ethics & legality — binding, every week.** All work in this course is **authorized, legal, defensive-minded** security practice performed **only inside the isolated lab you own** — the `appsec-lab` Docker network and its deliberately-vulnerable targets, with **no route to the internet or to any real third-party system**. Static analysis this week runs against the *published, intentionally-vulnerable source code* of your own lab targets (Juice Shop's public GitHub repository) — you are reading code, not attacking anyone. Dynamic analysis (ZAP) only ever points at `127.0.0.1`-published ports on your own lab network, never at a real site. Every scanner finding you triage gets the same attacker/defender treatment as every prior week: what it means, how to confirm it, how to fix it. Written authorization, a defined scope, and the law govern every exercise this week and every week after it.

## Learning objectives

By the end of this week, you will be able to:

- **Explain** what SAST, DAST, and SCA each detect and where each is structurally blind, and why a mature program runs all three rather than picking one.
- **Run** open-source scanners — Semgrep (SAST), OWASP ZAP (DAST), and Trivy/OSV-Scanner (SCA) — against your lab targets, including an authenticated DAST scan.
- **Triage** raw scanner output: confirm true positives with evidence, dismiss false positives with a written reason, and rank the rest by likelihood × impact.
- **Write** a custom Semgrep rule that catches an app-specific vulnerable pattern no generic ruleset flags, and prove it fires on the bad case and stays silent on the safe one.
- **Store and query** the full findings backlog in a database — SQLite via SQL and Python — extending the same `appsec.db` you've built since Week 1, never a spreadsheet.

## Prerequisites

- Week 1's isolated lab (`appsec-lab` Docker network, Juice Shop / DVWA / WebGoat) still standing, plus your `appsec.db` from Weeks 1–7 with its `targets`, `attack_surface`, and `risks` tables.
- Week 5's injection knowledge (source → sink, taint) — this week's SAST lecture reuses that mental model directly.
- Python 3.10+, `sqlite3` (ships with Python), `pip`, and Docker Desktop/Engine — same toolchain as every prior week.
- Comfortable reading JSON output from a command-line tool; you'll be parsing scanner reports with Python throughout.

## This week's map

Work top to bottom. Each piece assumes the ones before it.

| # | File | What's inside | ~Time |
|--:|------|---------------|------:|
| 1 | [lecture-notes/01-sast-reading-the-source.md](./lecture-notes/01-sast-reading-the-source.md) | How SAST models code and data flow, what it catches and misses, anatomy of a Semgrep rule | 2h |
| 2 | [lecture-notes/02-dast-probing-the-running-app.md](./lecture-notes/02-dast-probing-the-running-app.md) | Spidering and active-scanning a running app with ZAP, authenticated scans, reading alerts | 2h |
| 3 | [lecture-notes/03-sca-and-triage.md](./lecture-notes/03-sca-and-triage.md) | Dependency scanning against vulnerability databases, and the triage discipline that turns noise into a backlog | 2h |
| 4 | [exercises/exercise-01-run-a-sast-scan.md](./exercises/exercise-01-run-a-sast-scan.md) | Run Semgrep against Juice Shop's source; hand-triage five real findings | 1.5h |
| 5 | [exercises/exercise-02-run-a-dast-scan.md](./exercises/exercise-02-run-a-dast-scan.md) | Run a ZAP baseline scan, then an authenticated scan, against your running lab | 1.5h |
| 6 | [exercises/exercise-03-triage-into-a-database.md](./exercises/exercise-03-triage-into-a-database.md) | Load SAST + DAST + SCA output into `appsec.db`, normalize severities, query the backlog | 1.5h |
| 7 | [challenges/challenge-01-write-a-custom-sast-rule.md](./challenges/challenge-01-write-a-custom-sast-rule.md) | Write, test, and prove a Semgrep rule for an app-specific pattern | 1h |
| 8 | [challenges/challenge-02-reconcile-three-scanners.md](./challenges/challenge-02-reconcile-three-scanners.md) | Merge overlapping findings from three tools into one canonical, ranked list | 1h |
| 9 | [mini-project/README.md](./mini-project/README.md) | Wire all three scanners, triage the combined output, ship one risk-ranked backlog | 3h |
| 10 | [homework.md](./homework.md) | Extra practice, spread across the week | 4h |
| 11 | [quiz.md](./quiz.md) | 15 self-check questions + answer key | 1h |
| 12 | [resources.md](./resources.md) | Official docs + the few links worth your time | — |

## Weekly schedule

Adds up to roughly the course's full-time pace of **~28 hours**. Treat it as a target, not a stopwatch.

| Day | Focus | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Daily Total |
|-----------|------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|------------:|
| Monday | SAST — reading the source | 2h | 0h | 0h | 0.5h | 1h | 0h | 3.5h |
| Tuesday | Run Semgrep, hand-triage findings | 0h | 1.5h | 0h | 0.5h | 1h | 0h | 3h |
| Wednesday | DAST — probing the running app | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Thursday | SCA + triage discipline; backlog into SQLite | 2h | 1.5h | 0h | 0.5h | 1h | 0.5h | 5.5h |
| Friday | Custom rule + reconciling scanners | 0h | 0h | 2h | 0.5h | 1h | 0.5h | 4h |
| Saturday | Mini-project | 0h | 0h | 0h | 0h | 0h | 2h | 2h |
| Sunday | Quiz + review | 0h | 0h | 0h | 1h | 0h | 0h | 1h |
| **Total** | | **6h** | **4.5h** | **2h** | **3.5h** | **5h** | **3h** | **28h** |

## By the end of this week you can…

- Name, for any finding, which of SAST/DAST/SCA could have caught it — and which of the other two would have missed it and why.
- Run all three scanner classes against a lab target and get structured (JSON) output you can actually process.
- Look at a raw scanner alert and decide, with evidence, whether it's a true positive, a false positive, or a duplicate of something another tool already flagged.
- Write a Semgrep rule from scratch for a pattern that matters to a specific app, and prove it with a positive and a negative test case.
- Hold one queryable, risk-ranked findings backlog in SQLite that three different tools all feed into — the same discipline every findings report in this course has used since Week 1.

## Up next

[Week 9 — API security & software supply-chain security](../week-09-api-and-supply-chain-security/) — now that you can automate detection, you'll apply it to the two surfaces attackers increasingly go after first: your APIs and everything you didn't write yourself.

---

*Part of the Code Crunch Worldwide open curriculum · GPL-3.0 · If you find errors, please open an issue or PR.*
