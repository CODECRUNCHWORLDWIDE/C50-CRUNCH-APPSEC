# Mini-Project — A Complete STRIDE Threat Model of a Lab App

> Produce a complete, professional-grade STRIDE threat model of one application from your isolated lab: a data-flow diagram, per-element threats stored as queryable data, and a risk-ranked mitigation list you could hand to a real development team. This is the week's capstone — everything from the three lectures, all three exercises, and both challenges converges here into one deliverable.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges are behind you.

A threat model that lives only in your head, or only as a diagram nobody stores anywhere queryable, doesn't help a team ship safer software. This mini-project asks you to produce the artifact a real security engineer produces at the end of a real threat-modeling session: a diagram anyone can read, a database anyone can query, and a short report anyone can act on.

---

## Choose your target

Pick **one** application to model completely:

- **Juice Shop**, extended beyond this week's four flows to cover at least two more (e.g., product reviews/comments, the password-reset flow, or the file-upload feature if your Juice Shop version has one) — a deeper pass on a system you already partly modeled, **or**
- **DVWA or WebGoat**, extended beyond Challenge 1's scope to cover the whole app or a substantially larger slice of it — if you want a genuinely fresh, complete model instead of a deepening of one you've already started.

State your choice and your scope in one paragraph before you begin. The scope should be large enough to feel like a real deliverable — **at minimum 8 elements and 25 threats** — but you're still expected to time-box (Lecture 3, Section 5); this is not an invitation to model forever.

---

## Deliverable

A directory in your portfolio, `c50-week-02/mini-project/`, containing:

1. **`dfd.md`** — your Level 1 data-flow diagram (Mermaid), all four element types, every trust boundary marked and named, every flow labeled with the actual data it carries.
2. **`schema.sql`**, **`load_threats.py`**, **`threatmodel.db`** — the same schema pattern from Exercise 3 (`elements` + `threats` tables, `risk_score` generated from likelihood × impact), populated with **every** threat from your STRIDE-per-element pass, minimum 25.
3. **`queries.sql`** — at minimum the five query types from Exercise 3 (top risks, count by category, accepted risks, per-element, average risk per element), plus **one query of your own design** that answers a question none of the five standard ones do.
4. **`report.md`** — the risk-ranked mitigation report itself (see structure below): the actual deliverable you'd hand a development team.
5. **`notes.md`** — a short reflection (see the end).

---

## `report.md` structure

Write this as if a real engineering team will read it next week and use it to plan their sprint. Structure:

1. **Scope** (1 paragraph) — what you modeled and, just as importantly, what you deliberately left out and why.
2. **System diagram** — embed or link `dfd.md`.
3. **Top 10 risks** — a table generated from your top-risk query: element, STRIDE category, description, risk score, disposition, mitigation, one sentence each. This is the part of the document a busy engineering lead actually reads first — it must stand alone without requiring them to open the database.
4. **Coverage summary** — the count-by-category query's output as a table, with one sentence noting which STRIDE category your model found the most/fewest threats in, and a guess at why (was that category genuinely less present, or did your pass under-cover it?).
5. **Accepted risks** — every threat disposed as `accept`, with the one-sentence justification for accepting each. If you have none, state that explicitly and consider whether that's realistic (most real systems accept *something*).
6. **Recommendations for next steps** — 3–5 bullets mapping your top risks to which future weeks of this course (or which real-world practice) would address them, the way Lecture 3's control table did.

---

## Milestones

- **Milestone 1 (30 min):** Choose target, write your scope paragraph, confirm your lab container is healthy.
- **Milestone 2 (45 min):** Draw/extend the DFD. Aim for 8+ elements with all trust boundaries marked.
- **Milestone 3 (60 min):** Full STRIDE-per-element pass. Aim for 25+ threats across all 6 categories (fewer than 6 categories represented is a signal you rushed one — go back and check the element types you might have under-covered).
- **Milestone 4 (30 min):** Load into SQLite, run your queries, confirm the top-risk result matches your own instinct about what's scariest (and if it doesn't, reconcile why — same check as Exercise 3).
- **Milestone 5 (15 min):** Write `report.md` and `notes.md`.

---

## Rules

- **Store the threat model as data.** `report.md`'s tables must be generated *from* `queries.sql` output against `threatmodel.db` — not hand-typed independently of the database, which would let the two silently drift apart. If you edit a threat, edit it in the database and re-run the query.
- **Every threat needs a specific mitigation**, not a category. "Add security" is not a mitigation; "parameterize the SQL query building the login lookup" is.
- **Minimum 25 threats, 8 elements, all 6 STRIDE categories represented at least once somewhere in the model.**
- **No exploitation.** This entire deliverable is identification and planning, built by observing your own lab app's behavior and documented vulnerability classes — not by running an attack against it.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|---|---:|---|
| DFD correctness & completeness | 20% | Correct element types, all trust boundaries marked and named, 8+ elements |
| STRIDE coverage | 20% | 25+ threats, all 6 categories represented, correctly matched to element type |
| Scoring discipline | 15% | Every likelihood/impact number traceable to Lecture 3's rubric, no clustering at one value out of laziness |
| Data storage & queries | 15% | Schema matches the pattern, all required queries run cleanly, one original query adds real value |
| Report quality | 20% | `report.md` is genuinely usable by a non-security engineering lead without opening the database |
| Stated scope & assumptions | 10% | Scope paragraph is honest about what was and wasn't modeled |

---

## Reflection (`notes.md`, ~250 words)

1. Which STRIDE category was hardest to find real threats for on your chosen app, and why do you think that is — genuinely fewer threats there, or a blind spot in how you were looking?
2. Compare your top-risk query's #1 result to what you would have guessed *before* running the method. Did the systematic pass surface something your gut missed, or confirm what you already suspected? Either answer is fine — the point is noticing which.
3. If you had another full day on this exact model, what would you do next — go deeper (Level 2 DFD on one process) or wider (cover more flows)? Justify with Lecture 3 Section 5's "depth follows risk" rule.
4. One sentence: what would you need in order to turn this threat model into a verified set of penetration-test findings? (Foreshadows Week 3.)

---

## Why this matters

This is the deliverable real AppSec engineers produce, over and over, for real systems — a diagram, a database, and a report that turns "I have a bad feeling about this design" into something a team can put in a sprint. Keep `threatmodel.db`; Week 3's OWASP Top 10 work will let you verify some of these threats for real, in your same lab, under the same authorization discipline.

When done: push, then take the [quiz](../quiz.md) and start [Week 3 — The OWASP Top 10, in depth](../../week-03-owasp-top-10-in-depth/).
