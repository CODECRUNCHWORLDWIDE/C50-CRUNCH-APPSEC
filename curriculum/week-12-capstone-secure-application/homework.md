# Week 12 — Homework

Five problems, ~4 hours total, spread across the week. All work happens against your own Crunch Ledger lab (or your own chosen target), on `127.0.0.1`, inside your isolated capstone lab — nothing here ever points at a system you don't own. Commit each deliverable.

---

## Problem 1 — Explain the whole capstone to a non-technical stakeholder (45 min)

Write `explain-the-capstone.md`, no more than 350 words, aimed at a hypothetical new hire's manager who has never seen a threat model or a findings database. It must:

1. Describe what Crunch Ledger does and who uses it — no security jargon in this paragraph at all.
2. Name, in plain language, the single riskiest thing that was wrong with it before this week (pick your own worst originally-seeded vulnerability) and what it would have meant in practice if it had shipped that way.
3. State what changed and how you know it's actually fixed (one sentence on the re-test discipline, in plain language — "we wrote an automated check that tries the old attack and confirms it now fails").

**Deliver** `explain-the-capstone.md`. This is the same stakeholder-translation skill Week 1 and Week 6 both asked for — the capstone is where you prove you can do it for a whole application, not just one finding.

---

## Problem 2 — Threat-model a feature that doesn't exist yet (60 min)

Crunch Ledger is getting a new feature: **expense report export**, where a manager can download a CSV of all their team's approved expenses for a given month. Before any code exists, in `export-feature-threat-model.md`:

1. Add the new route (`GET /expenses/export?month=YYYY-MM`) to a copy of this week's DFD.
2. Run the full STRIDE checklist against just this one new element — at minimum, name the IDOR-shaped risk (can a manager export another team's data by changing a parameter?) and the DoS-shaped risk (can an unbounded date range or a very large team trigger an expensive query?).
3. Write the one query-level fix (in the `WHERE`-clause style Lecture 2 taught) that closes the access-control risk, without actually building the full feature.

**Deliver** `export-feature-threat-model.md`. Threat-modeling a feature before it's built, not after a scanner finds the gap, is the entire point of Week 2 and this capstone both — this problem asks you to do it once more, cold, on something genuinely new.

---

## Problem 3 — Audit a stranger's "secure" claim (45 min)

A colleague on a different team tells you: "our app is secure, we ran a scanner and it came back clean." In `audit-the-claim.md` (~250 words):

1. List at least four things a clean SAST/DAST/SCA scan does **not** prove, drawing on this week's own experience (the manager-approving-their-own-expense gap, for instance, which no scanner found).
2. Propose three specific questions you'd ask this colleague before trusting the "secure" claim (e.g., "was there a written scope and threat model, or did the scan run against whatever routes happened to exist?").
3. State, in one sentence, why "a clean scan" and "a secure application" are not the same claim.

**Deliver** `audit-the-claim.md`.

---

## Problem 4 — Write the CVE-style advisory for your own worst finding (60 min)

Pick the single most severe vulnerability you found and fixed in Crunch Ledger this week (or your own app's equivalent). In `self-advisory.md`, write it up in the structure of a real public vulnerability advisory (model it on a real CVE or GitHub Security Advisory you look up for format only — do not copy their content):

1. **Title** — one line, naming the vulnerability class and the affected component.
2. **Description** — what the flaw is, in the precise technical language this course has used all along.
3. **Impact** — what an attacker (in your lab, hypothetically) could actually do with it.
4. **Affected versions** — your capstone repo's commit hash before the fix.
5. **Fix** — the commit hash after the fix, and one sentence on the pattern used.
6. **Credit** — you, since you both found and fixed it.

**Deliver** `self-advisory.md`. Writing a finding in this exact format is a real, transferable skill — this is the shape every responsible-disclosure report and every internal security bulletin takes.

---

## Problem 5 — Extend the DAST probe for a feature you didn't build (30 min)

Take Homework Problem 2's not-yet-built export feature and write the DAST probe check you **would** run against it once it exists — a `check_export_idor()` function in the style of Exercise 3's `dast_probe.py`, that asserts a manager cannot export another team's data by changing the route's parameters. You are writing a test for code that doesn't exist yet; that's deliberate — a well-written test written before the feature, from the threat model alone, is proof the threat model was specific enough to be actionable, not just descriptive.

**Deliver** the function, appended to a new file `future-checks.py`, with a one-line comment explaining what it would assert and why, ready to activate the moment the feature ships for real.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 60 min |
| 3 | 45 min |
| 4 | 60 min |
| 5 | 30 min |
| **Total** | **~4h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
