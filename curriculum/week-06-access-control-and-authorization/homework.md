# Week 6 — Homework

Five problems, ~5 hours total, spread across the week. All work happens against your own `crunch-helpdesk` lab, on `127.0.0.1`, inside your isolated `appsec-lab` — nothing here ever points at a system you don't own. Commit each deliverable.

---

## Problem 1 — Explain an IDOR to a non-technical stakeholder (45 min)

Pick your Exercise 1 cross-tenant IDOR finding. Write `explain-the-idor.md`, no more than 300 words, aimed at a hypothetical product manager with zero security background. It must:

1. Describe the finding **without any security jargon** (no "IDOR," "object reference," "authorization" — describe the actual thing that could go wrong: "any logged-in customer could read any other customer's support tickets by changing a number in the web address").
2. State the concrete business consequence — whose data, how much of it, and what a competitor or a customer could actually learn.
3. Recommend one next step, phrased the way you'd actually say it in a meeting.

**Deliver** `explain-the-idor.md`. This is the same translation skill Week 1 asked for, applied to this week's specific flaw class — you'll need it in every findings report from Week 11 onward.

---

## Problem 2 — Design RBAC for a new feature, on paper first (60 min)

`crunch-helpdesk` is getting a new feature: **internal notes** on a ticket, visible only to `agent`/`manager`/`admin` roles (never `member`, since these notes may contain internal handling context the customer shouldn't see), and editable only by the note's author or a `manager`/`admin`.

In `internal-notes-design.md`:

1. Design the schema for a `ticket_notes` table (columns, types, foreign keys).
2. List the exact new permissions this feature needs and which roles get them — as an `INSERT` statement into `role_permissions`, matching Lecture 1, Section 2.1's exact style.
3. Write the `can_view_note` and `can_edit_note` function signatures (Lecture 1, Section 3's style) in plain Python, including the tenant check.
4. Do **not** implement the route yet — the point of this problem is designing the policy correctly on paper before any code exists, the habit Week 2's STRIDE threat modeling also drilled.

**Deliver** `internal-notes-design.md`. You may implement this for real as a mini-project stretch goal, but the deliverable here is the design.

---

## Problem 3 — Find the missing case in someone else's policy (45 min)

Below is a role-permission table someone else designed for a different app (a simple document-sharing tool). Find the gap:

| Permission | viewer | editor | owner |
|---|:---:|:---:|:---:|
| view document | ✅ | ✅ | ✅ |
| edit document | — | ✅ | ✅ |
| delete document | — | — | ✅ |
| share document with a new viewer | — | ✅ | ✅ |
| **revoke** a viewer's access | — | — | — |

In `policy-gap.md` (~200 words): what's the practical consequence of no role holding "revoke a viewer's access"? Is this a security bug, a product gap, or both? What role(s) should get this permission, and why does it matter that it's *not* automatically the same set of roles that can *grant* access (Section 5's "grant" and "revoke" aren't symmetric by default — argue whether they should be, for this specific app)?

**Deliver** `policy-gap.md`.

---

## Problem 4 — Horizontal vs. vertical, five real-world examples (45 min)

In `escalation-examples.md`, describe five **real, publicly-documented** access-control vulnerabilities (search "CVE IDOR" or "CVE privilege escalation" plus a well-known product name, or use a public vulnerability database/advisory), and for each, in one or two sentences:

1. Classify it as horizontal, vertical, or both.
2. State, in your own words, what check was missing.

This is research and classification only — you are not reproducing or testing any of these against a real system, only reading public advisories and classifying what you read.

**Deliver** `escalation-examples.md` with five entries, each citing its source (CVE ID or advisory URL).

---

## Problem 5 — Extend the proof matrix defensively (60 min)

Take Exercise 3's `expected_matrix.py` and add **10 new rows** specifically designed to catch a mistake a careless "fix" might introduce — not just re-testing what's already fixed. Examples of the kind of case to add: a role that should be denied getting accidentally granted permission on a route you didn't originally test; an account testing a permission that exists in `role_permissions` for the *wrong* role by a copy-paste accident; a company-3 scenario (add a third fictional company and one user to it) to make sure your tenant checks generalize past exactly two companies.

**Deliver** the 10 new rows appended to `expected_matrix.py`, plus a short `matrix-additions-notes.md` explaining what failure mode each new row is specifically designed to catch.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 60 min |
| 3 | 45 min |
| 4 | 45 min |
| 5 | 60 min |
| **Total** | **~4h 15m** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
