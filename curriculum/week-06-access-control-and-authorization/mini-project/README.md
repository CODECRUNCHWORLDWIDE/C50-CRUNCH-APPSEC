# Mini-Project — Rebuild `crunch-helpdesk` to Fail Closed

> Take `crunch-helpdesk` — riddled, at the start of this week, with IDOR and privilege-escalation flaws — and rebuild its authorization end to end: a documented RBAC/ABAC model, object-level ownership checks on every route that touches a specific resource, and a data-driven role × resource test matrix proving, with evidence, that every access decision is enforced **server-side**, on every request, denying by default.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

This is the week's capstone: proof that you can take a real application from "checks login, nothing else" to "documents its authorization model, enforces it in one auditable place per concern, and can prove — not assert — that the enforcement holds across every role and every tenant." That shape (model → enforce → prove) is the actual day-to-day discipline of an access-control review, and it's the shape every later review in this course reuses.

---

## Deliverable

A directory in your portfolio `c50-week-06/mini-project/` containing:

1. `authz-model.md` — your documented RBAC/ABAC policy (build on Lecture 1, don't restart it).
2. `crunch-helpdesk/` — the fully hardened app: `app.py`, `schema.sql`, `rbac_schema.sql`, `seed.py`, and `crunchhelpdesk.db` populated.
3. `proof_matrix.py` + `proof_results.db` — the complete role × resource × action test matrix, extended past Exercise 3 and Challenge 1/2's coverage.
4. `report.md` — a written summary tying it all together (structure specified below).

---

## Requirements

### Part 1 — Document the authorization model (`authz-model.md`)

Write down, as a real reference document (not implied by scattered code comments):

- The complete role-permission matrix — every role, every permission, exactly which grants which (Lecture 1, Section 2, extended with anything added in the challenges).
- Every object-level (ABAC) rule in plain language and as a function signature, e.g. `can_view_ticket(user, ticket) -> bool`, `can_close_ticket(user, ticket) -> bool`, `can_reassign_ticket(user, ticket, new_assignee) -> bool` — the last one must explicitly name **both** identifiers it checks, per Challenge 2's finding.
- The tenant-isolation rule, stated once, explicitly, as the floor check that runs before role or ownership logic on every object-touching route.
- One sentence per route in the app stating which of the three layers (authentication, RBAC, ABAC/tenant) apply to it and why.

### Part 2 — Harden every route (`crunch-helpdesk/`)

- Every route in the app has been audited against Lecture 3, Section 5's four-question checklist; `authz-model.md`'s per-route sentence and the actual code must agree.
- The `ticket:close` permission from Challenge 1 and the reassignment tenant fix from Challenge 2 are both present, whether or not you completed those challenges beforehand.
- Add **one new route** not present in the original app — `DELETE /tickets/<id>` (admin/manager only, same-company only) — and build its authorization correctly, from scratch, using this week's patterns, as proof you can apply the discipline to code you haven't seen before rather than just fixing what was handed to you.
- Wire in Lecture 3, Section 4.1's deny-by-default `before_request` hook, and verify it actually blocks a route with `@require_permission` deliberately removed (test this, then put the decorator back).

### Part 3 — The proof matrix (`proof_matrix.py`)

- **At least 40 rows**, covering all 8 seeded users, every route in the app (including your new `DELETE /tickets/<id>`), and both tenant directions.
- At least 4 rows specifically targeting the reassignment two-identifier case from Challenge 2 (ticket and assignee from mismatched companies, in both directions).
- At least 4 rows specifically targeting the `ticket:close` role/assignment distinction from Challenge 1 (member, unassigned agent, assigned agent, manager).
- Every row passes on your final run — `SELECT COUNT(*) FROM proof_results WHERE passed = 0` returns `0`.

### Part 4 — `report.md`

Write a short report covering:

1. **Executive summary** (~150 words) — as if handing this to a non-technical stakeholder: what was broken, what "broken" actually meant in plain terms (not jargon), and what's true now.
2. **Before/after table** — every flaw from this week's README table (six original flaws, plus Challenge 1's and Challenge 2's), each with the exact fix applied and the proof-matrix row(s) that verify it's closed.
3. **The one gap you're least confident about** — every real system has one; name it honestly, explain why you're unsure, and what you'd need to do to close that uncertainty (this mirrors Week 1's honesty-about-limits standard).
4. **Reflection** (~150 words): which of the two failure shapes — IDOR or privilege escalation — took longer to fully close, and why? What made the two-identifier reassignment case (Challenge 2) or the wrong-permission case (Challenge 1) harder to spot than the original, more obvious flaws?

---

## Milestones

- **Milestone 1 (45 min):** `authz-model.md` complete and internally consistent — every route's stated authorization layers match what Lecture 1–3 and the exercises established.
- **Milestone 2 (60 min):** Every route hardened, `DELETE /tickets/<id>` added and working, deny-by-default hook verified.
- **Milestone 3 (60 min):** Proof matrix built to 40+ rows and passing 100%.
- **Milestone 4 (15 min):** `report.md` written, proofread as if a non-technical reader sees the executive summary first.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Model documentation | 20% | `authz-model.md` is complete, precise, and matches the actual code exactly — no drift between the two |
| Route hardening | 25% | Every original flaw closed, `ticket:close` and reassignment fixes present, new `DELETE` route correctly scoped from scratch |
| Deny-by-default | 15% | `before_request` hook implemented and demonstrably blocks an undecorated route |
| Proof matrix rigor | 25% | 40+ rows, full coverage including both named edge cases, 100% passing on final run |
| Report clarity & honesty | 15% | Executive summary readable by a non-technical stakeholder; the "least confident" section is genuinely honest, not padding |

---

## Why this matters

Broken access control has topped the OWASP Top 10 since 2021 precisely because "did every route remember every check" doesn't scale past a handful of endpoints without becoming a documented model, a small number of enforcement primitives (permission decorator, ownership-filtered query, tenant floor check), and a systematic proof — the exact three-part shape this project asked you to build. Every later week's mini-project reuses this pattern: model the policy, enforce it in as few auditable places as possible, and prove coverage with data instead of memory.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 7 — Cryptography basics for developers](../../week-07-cryptography-basics-for-developers/).
