# Mini-Project — Isolated Lab, Attack Surface, and a Signed Risk Register

> Stand up your isolated lab, map a vulnerable app's attack surface, and produce a risk register — assets, threats, and risk scores — in SQLite, plus a signed rules-of-engagement document. This is the week's capstone: proof you can do, end to end, what a security engineer actually does before writing a single line of a fix.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

A real security review never starts with "let's find bugs." It starts with **authorization** (can I even do this), **scope** (what exactly), **inventory** (what's actually there), and **prioritization** (what matters most). This mini-project has you produce all four, tied together into one coherent deliverable — the shape every findings report in this course, all the way to the Week 12 capstone, will follow.

---

## Deliverable

A directory in your portfolio `c50-week-01/mini-project/` containing:

1. `rules-of-engagement.md` — your signed authorization/scope document (build on Challenge 1, don't restart it).
2. `lab-setup.sh` / `lab-teardown.sh` — your working lab scripts (from Exercise 1), confirmed working.
3. `appsec.db` — your SQLite database with `targets`, `attack_surface`, `assets`, `threats`, and `risks` tables populated (from Exercises 2–3), extended per the requirements below.
4. `report.md` — a written summary tying it all together (structure specified below).

---

## Requirements

### Part 1 — Lab and authorization (verify, don't redo)

- `lab-setup.sh` runs cleanly and stands up all three targets.
- Isolation is verified per Exercise 1's checks — confirm again, don't just trust last week's result.
- `rules-of-engagement.md` names all three targets explicitly in scope, and states the testing window as this project's completion date.

### Part 2 — Attack surface (extend Exercise 2)

- **At least 15 attack-surface entries** across **at least two** of your three targets (Juice Shop plus one of DVWA/WebGoat — seeing the same category of entry point on a second application is the point).
- At least one entry of type `admin_interface` and at least one of type `file_upload` or `third_party_integration` somewhere in your set.

### Part 3 — Risk register (extend Exercise 3)

- **At least 12 scored risks**, spanning all three CIA properties (confidentiality, integrity, availability) at least twice each.
- Scores must show real variation — your register should have entries in at least three of the four risk bands (Low/Medium/High/Critical), not everything clustered at one level.
- Every `justification` field is a genuine sentence explaining the specific likelihood and impact reasoning — not a copy-pasted template.

### Part 4 — `report.md`

Write a short report covering:

1. **Executive summary** (~150 words) — as if handing this to a non-technical stakeholder: what did you look at, what did you find, what matters most, in plain language.
2. **Top 5 risks table** — pulled straight from a `SELECT ... ORDER BY risk_score DESC LIMIT 5` query, with `entry_point`, `vulnerability`, `risk_score`, and a one-line plain-English translation of each.
3. **One query that surprised you** — run something exploratory against your own database (e.g., "which asset has the highest average risk?", "how many unauthenticated entry points accept input?") and report what you found and why it mattered.
4. **Reflection** (~150 words): What was hardest — building the lab, mapping the surface, or scoring risk honestly? Where did you catch yourself wanting to skip the "why" and just assign a number?

---

## Milestones

- **Milestone 1 (30 min):** Confirm lab is up, isolation verified, RoE finalized and "signed."
- **Milestone 2 (60 min):** Extend attack-surface mapping to a second target; hit the 15-entry minimum.
- **Milestone 3 (60 min):** Extend the risk register to 12+ scored entries with real CIA and score variation.
- **Milestone 4 (30 min):** Write `report.md`, run the five report queries, and proofread the executive summary as if a non-technical reader will see it first.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Lab correctness & isolation | 20% | Lab stands up cleanly; isolation is actually re-verified, not assumed |
| Attack-surface coverage | 20% | 15+ entries, two targets, honest notes, real diversity of entry types |
| Risk-register rigor | 30% | 12+ risks, CIA and score variation, every justification is genuinely reasoned |
| Report clarity | 20% | Executive summary is readable by a non-technical stakeholder; top-5 table is pulled from a real query |
| RoE precision | 10% | Scope is specific and matches the actual lab; out-of-scope is explicit |

---

## Why this matters

This is the smallest complete loop of professional AppSec work: authorize, inventory, prioritize, report. Every later week of this course adds *depth* to one of these four steps — Week 2 formalizes inventory into STRIDE threat modeling, Week 3 gives you the Top 10's specific vocabulary for what you find, and Week 11 turns `report.md` into a polished, professional findings report. Keep `appsec.db` — you'll extend the same schema, not rebuild it, for the rest of this course.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 2 — Threat modeling with STRIDE](../../week-02-threat-modeling-with-stride/).
