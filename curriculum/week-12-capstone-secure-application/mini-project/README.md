# Mini-Project — Ship a Secure Application

> Assemble everything this week produced into one deliverable: a small application, threat-modeled with STRIDE, built or hardened with the course's security controls, hunted with automated and manual review in your isolated lab, remediated and re-tested end to end, and shipped with a defensible residual-risk sign-off. This is the proof that twelve weeks of Crunch AppSec actually happened.

**Estimated time:** 3 hours, best done Saturday after all three exercises and both challenges are complete — this mini-project assembles their outputs into one package, it doesn't ask you to redo the work from scratch.

Unlike every earlier week's mini-project, this one introduces nothing new. It asks you to package the whole capstone — threat model, build, hunt, remediation, defense — into one artifact a stranger could pick up cold and trust: a hiring manager evaluating your portfolio, a teammate inheriting your app, a security reviewer who wasn't in the room for any of the last five days.

---

## Deliverable

A directory in your portfolio, `c50-week-12/mini-project/`, containing:

1. **`SCOPE.md`** — your written scope and authorization statement (Exercise 1).
2. **`THREAT-MODEL.md`** — the data-flow diagram, full STRIDE table, and a rendering of the final state of `risk_register` (Exercise 1).
3. **The application source** — `app.py`, `config.py`, `requirements.txt`, `schema.sql`, `seed.py`, `ci_pipeline.yml`, fully hardened (Exercises 2, Challenge 1).
4. **`capstone_findings-export.sql`** — a dump of the final `capstone_findings` table, taken with `sqlite3 capstone_findings.db .dump > capstone_findings-export.sql`, showing **zero** open findings (Exercise 3, Challenge 1).
5. **`RESIDUAL-RISK.md`** — the signed-off residual-risk statement (Challenge 2).
6. **`SECURE-APPLICATION-REPORT.md`** — the centerpiece narrative deliverable, structured per the requirements below.

---

## Requirements

### Threat model (from Exercise 1)

- `SCOPE.md` is accurate to the final state of the app, not just its Monday starting point.
- The STRIDE table includes at least one finding that came purely from threat-modeling — no corresponding scanner or manual-review row — and is explicitly labeled as such.
- `risk_register` shows every row's final `status` (`mitigated` or a justified `accepted`), not just `open`.

### Secure build (from Exercise 2, Lecture 2)

- All eleven originally-seeded vulnerabilities are fixed at the source, each fix matching the *pattern* the corresponding lecture section taught (query-level ownership filter, not a bolted-on `if`; `hmac.compare_digest`, not a workaround; environment-injected secrets, not a "less obvious" hardcoded value).
- The app still runs and its core functionality (login, submit an expense, approve an expense, search) works correctly for the roles that should be able to use it — a secure app that's also broken isn't a passing capstone.

### Hunt and remediation (from Exercise 3, Challenge 1)

- `capstone_findings` shows zero `open` rows; every row is `retested_ok` or a justified `wont_fix`.
- At least one finding came from each of the four sources (`sast`, `dast`, `sca`, `manual_review`) and at least one finding is **not** one of the eleven originally-seeded vulnerabilities.
- The self-approval business-logic gap (or your own custom app's equivalent design-level flaw) is closed and re-tested.

### Defense (from Challenge 2)

- `RESIDUAL-RISK.md` lists at least one real, specific accepted risk with a stated likelihood, impact, reasoning, and a concrete "revisit if" condition.
- You can answer, from memory and without opening the code, all eight of Challenge 2's review questions.

---

## `SECURE-APPLICATION-REPORT.md` structure

Write this as the single document that ties every artifact together — the one a reviewer reads first and everything else supports:

1. **Executive summary** (half a page, no jargon). What the app does, what was found, what shipped, what's explicitly accepted as risk.
2. **Target and scope.** A short restatement of `SCOPE.md` — what was in bounds, what wasn't, and why.
3. **Threat model summary.** The DFD, the STRIDE table (or a representative excerpt if it's long), and the top three `P0`/`P1` risks from the register with their final status.
4. **Security controls built in.** One paragraph per control category — auth/session, injection defense, access control, secrets/crypto, API/supply-chain, CI/CD — naming the specific pattern used and the specific vulnerability it closed.
5. **Hunt and findings.** A table: source, count found, count fixed, count accepted. One sentence on what the manual review found that no tool did.
6. **Remediation evidence.** A pointer to `capstone_findings-export.sql` and a description of how re-tests were performed (DAST probe re-run, Bandit re-run, manual re-check) — evidence, not a claim.
7. **Residual risk and sign-off.** The content of `RESIDUAL-RISK.md`, inline, with your name and today's date as the accountable owner of the decision.
8. **What you'd do next.** If you had another week, what's the next thing you'd threat-model, build, or fix — proof the capstone is a snapshot of good judgment, not a claim that the app is now perfect forever.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Threat model quality | 20% | DFD and STRIDE table are complete and specific to the actual app; at least one finding came purely from reasoning, not tooling |
| Secure build coverage | 25% | All eleven vulnerabilities fixed with the correct pattern, not a workaround; app still functions correctly for legitimate use |
| Hunt and triage rigor | 20% | All four finding sources represented; at least one genuinely new finding beyond the eleven; zero open findings at submission |
| Remediation evidence | 15% | Every closed finding has a real, repeatable re-test recorded, not a narrative claim |
| Defense and residual risk | 20% | Residual-risk statement is specific and defensible; all eight review questions answerable from memory |

---

## Why this matters

Every skill in this course exists to produce exactly one outcome under real conditions: an application you can point to and say, specifically and with evidence, "here is what could go wrong, here is what I did about it, and here is what I'm choosing to accept and why." That is not a security checklist — it is a professional judgment call, backed by proof, the same call every real engineering team makes before every real release. If you can do this — threat-model, build it in, hunt it down, remediate it, and defend it — you can walk onto a real application security team, or simply ship your own software, and do the job the way it's actually done. That's the whole point of twelve weeks.

When done: push your work, take the [quiz](../quiz.md), and you're finished with **C50 · Crunch AppSec**. See the week [README](../README.md)'s "Course complete" section for where to go next.
