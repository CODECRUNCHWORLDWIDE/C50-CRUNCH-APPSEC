# Week 8 — Homework

Five problems, ~4 hours total, spread across the week. All scanning happens against your own isolated lab and your own cloned copy of your lab target's published source — nothing here ever points at a system you don't own. Commit each deliverable.

---

## Problem 1 — Scan a second target with all three tools (60 min)

Everything this week ran against Juice Shop. Pick **DVWA or WebGoat** (whichever you used less in Week 1) and run Semgrep against its source (clone it, same as Exercise 1) and Trivy against its dependency manifest. (DAST is optional here if the target's login flow is more complex — a baseline ZAP scan is enough.)

In `second-target-comparison.md` (~300 words), compare: did the same categories of finding show up (e.g., injection-shaped SAST findings), did the *volume* of findings differ substantially from Juice Shop, and — most importantly — does a pattern you triaged as a true positive in Juice Shop appear to repeat in this second app in a genuinely similar shape?

**Deliver** `second-target-comparison.md` plus the raw scan output files. Seeing the same vulnerability *class* recur across genuinely different codebases is what makes "know the OWASP Top 10 cold" (Week 3) actually pay off when you're the one running the scanner.

---

## Problem 2 — Defend a severity disagreement (45 min)

Find one finding in your `appsec.db` where you believe the **scanner's own severity rating** (`severity_raw`) and **your triaged risk score** (`likelihood × impact`) meaningfully disagree — e.g., a Trivy `HIGH`-severity CVE you scored as a low risk because of the reachability problem (Lecture 3, Section 3), or conversely a `WARNING`-level Semgrep finding you scored as a high risk because of app-specific context the rule author couldn't have known.

In `severity-disagreement.md` (~250 words), state the finding, the scanner's rating, your score, and a rigorous justification for the gap — this is the single most important judgment call this week teaches, and it deserves a real writeup, not a one-line note.

**Deliver** `severity-disagreement.md`.

---

## Problem 3 — Write a second custom rule, on a different pattern (60 min)

Challenge 1 had you write one custom Semgrep rule. Write a **second** one, for a **different kind of pattern** than your first — if Challenge 1 covered an injection-shaped sink, write this one for something structurally different: an insecure-deserialization pattern, a missing-authorization-check shape (an endpoint handler that reads an `:id` path parameter and queries a resource with no ownership check — genuinely hard for generic SAST, and a good test of your own rule-writing skill against Week 6's IDOR material), or a weak-cryptography-primitive call.

Prove it the same way as Challenge 1: a `test-vulnerable` file it fires on, a `test-safe` file it doesn't, and a short `rule-2-rationale.md` explaining the pattern.

**Deliver** `custom-rule-2.yaml`, `test-vulnerable-2.js`, `test-safe-2.js`, `rule-2-rationale.md`. Two rules is meaningfully different practice than one — the first time you write a Semgrep rule you're following Lecture 1's template; the second time you're actually applying the pattern-language reasoning yourself.

---

## Problem 4 — Explain a scanner's blind spot to a skeptical engineer (45 min)

Imagine a backend engineer on your team says: "we ran Semgrep and it came back clean, so this endpoint is secure." In `scanner-blind-spot.md` (~300 words), write the response you'd actually give — respectfully, but precisely correcting the claim. Use a **specific, concrete example** (not a generic "tools aren't perfect" hand-wave): describe one actual vulnerability class from this week's lectures (a missing-authorization IDOR is the strongest example, tying back to Week 6) that a clean Semgrep run genuinely would not catch, and explain *why*, using the source-vs-shape reasoning from Lecture 1, Section 3.

**Deliver** `scanner-blind-spot.md`. Translating a tool's limitation into a claim a non-security engineer will actually update their mental model from is worth as much as running the tool correctly in the first place.

---

## Problem 5 — Time and log a full pipeline re-run (50 min)

Prove your Mini-Project's `pipeline.sh` actually works from a clean state, the same discipline Week 1's lab-rebuild homework drilled:

1. Tear down and rebuild your lab from scratch (`lab-teardown.sh` / `lab-setup.sh` from Week 1).
2. Run `pipeline.sh` timed, start to finish, against the freshly rebuilt lab.
3. In `pipeline-rebuild-log.md`, record the total time, whether any step failed on the clean rebuild that had silently depended on leftover state from a previous run, and one concrete improvement you'd make to the pipeline if you were running it as a real weekly CI job.

**Deliver** `pipeline-rebuild-log.md`. A scanning pipeline that only works because of leftover state from last time you ran it isn't a pipeline — it's a fragile demo, and Week 10's CI/CD material assumes exactly this kind of clean-state reliability.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 60 min |
| 2 | 45 min |
| 3 | 60 min |
| 4 | 45 min |
| 5 | 50 min |
| **Total** | **~4 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
