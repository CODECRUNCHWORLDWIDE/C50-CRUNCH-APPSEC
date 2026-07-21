# Week 1 — Homework

Five problems, ~4 hours total, spread across the week. All work happens against your own isolated lab from Exercise 1 — nothing here ever points at a system you don't own. Commit each deliverable.

---

## Problem 1 — Explain risk to a non-technical stakeholder (45 min)

Pick any one finding from your Exercise 2 attack surface or Exercise 3 risk register. Write `explain-the-risk.md`, no more than 300 words, aimed at a hypothetical product manager with zero security background. It must:

1. Describe the finding **without any security jargon** (no "IDOR," "XSS," "CIA triad" — describe the actual thing that could go wrong, in plain language).
2. State the risk score and translate it into a business consequence ("this could expose every customer's order history to anyone who finds this page" rather than "risk score 16").
3. Recommend one next step, phrased the way you'd actually say it in a meeting.

**Deliver** `explain-the-risk.md`. This skill — translating a technical finding into a decision a non-technical stakeholder can act on — is worth as much as the technical finding itself, and you'll need it every week from Week 3 onward when you write real findings against the OWASP Top 10.

---

## Problem 2 — Score five more risks, on purpose varied (60 min)

Your Exercise 3 risk register likely leans toward "everything feels risky" (a common Week 1 pattern — everything is new, so everything feels alarming). Go back to your `appsec.db` and add **5 more** scored risks specifically chosen to **not** all be high:

1. One that should score **Low** (1–4) — something real but genuinely low-consequence (a cosmetic issue, or something requiring implausible access).
2. One that should score **Medium** (5–9).
3. One that should score **High** (10–15).
4. One that should score **Critical** (16–25).
5. One where you genuinely can't decide between two adjacent bands — score it, then write **two sentences** explaining the ambiguity and which way you leaned.

**Deliver** the 5 new `INSERT` statements in `homework-risks.sql`, plus a short `homework-risks-notes.md` explaining problem 5's ambiguous case. The skill here is resisting the pull toward "everything is a 5" — a register where every score is identical isn't prioritizing anything.

---

## Problem 3 — Trust boundary walkthrough on a second target (45 min)

Using DVWA or WebGoat (whichever you haven't focused on yet), pick **one** feature (e.g., DVWA's file upload, WebGoat's HTTP Basics lesson) and, in `trust-boundaries.md`, diagram or describe (prose is fine, a Mermaid diagram is better practice) every trust boundary the request crosses from your browser to wherever the data ends up — following Lecture 2, Section 5's pattern exactly.

**Deliver** `trust-boundaries.md` with at least 3 identified boundaries and, for each, one sentence on what check *should* exist there.

---

## Problem 4 — The economics argument, applied to a real decision (45 min)

Lecture 1, Section 3 covered the economic asymmetries between attackers and defenders. In `economics-argument.md` (~350 words), apply that reasoning to a concrete, hypothetical decision: *"Should a small startup with 3 engineers spend a week adding rate limiting to its login endpoint, or ship the next feature instead?"*

Address:

1. What's the *deferred, probabilistic* cost of not doing it (tie to Lecture 1, Section 1)?
2. What's the *immediate, certain* benefit of shipping the feature instead?
3. Using the risk = likelihood × impact framework from Lecture 2, make an actual argument for which choice is more defensible — and be honest if the answer is genuinely close, rather than forcing a dramatic conclusion.

**Deliver** `economics-argument.md`. There's no single correct verdict — the grade is in whether you used the actual frameworks from this week's lectures, not gut feeling.

---

## Problem 5 — Rebuild the lab from nothing, timed (45 min)

Prove your Exercise 1 automation actually works, not just once while you were building it:

1. Fully tear down your lab: `./lab-teardown.sh`.
2. Time yourself running `./lab-setup.sh` from a completely clean state, through all three isolation checks from Exercise 1, Task 3.
3. In `rebuild-log.md`, record: how long the full rebuild-and-verify cycle took, whether anything broke that worked before, and one improvement you'd make to the scripts if you were doing this weekly for the rest of the course (you are).

**Deliver** `rebuild-log.md`. A lab you can only stand up once, by luck, isn't a lab — it's a demo. This habit is what makes Weeks 2–12 fast to start instead of a fight with tooling every Monday.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 60 min |
| 3 | 45 min |
| 4 | 45 min |
| 5 | 45 min |
| **Total** | **~4 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
