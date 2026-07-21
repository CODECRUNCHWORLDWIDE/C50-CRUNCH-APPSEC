# Exercise 2 — Taint-Trace a Flaw by Hand

**Goal:** Produce full hop-by-hop taint traces — in the style of Lecture 2's worked examples — for the two flaws you confirmed in Exercise 1: the SQL injection in `/invoices/search`, and the missing authorization check in `/invoices/export`. Precision matters more than speed here: every hop needs a real location and a real answer to "sanitized or not, for this specific sink."

**Estimated time:** 90 minutes.

## Setup

`pr-482.diff` applied, app running, `raw-notes.md` from Exercise 1 in hand as your starting suspicions.

## Task 1 — Trace the injection, hop by hop (30 min)

In `trace-injection.md`, reproduce Lecture 2 Section 2's table format for `/invoices/search`, filled in from **your own reading of the code** (don't copy the lecture's table — write it yourself and confirm it matches):

| Hop | Location | Expression | Tainted? | Real sanitizer applied? |
|---|---|---|---|---|
| 1 | … | … | … | … |
| 2 | … | … | … | … |
| 3 | … | … | … | … |
| 4 | … | … | … | … |
| Sink | … | … | — | … |

Then answer, in prose, directly beneath the table:

1. At which exact hop does the untrusted value first become dangerous — i.e., at which hop does it first get spliced into something that will be interpreted as code rather than treated as data?
2. Is there **any** hop between the source and the sink where a real sanitizer could have been applied but wasn't? Name the hop and what a real fix would look like there.
3. Both `term` and `status_filter` are tainted sources here. Does either one reach the sink through a *different* path than the other? Trace `status_filter` separately if its path differs at all from `term`'s.

## Task 2 — Trace the authorization gap, hop by hop (30 min)

`/invoices/export`'s flaw isn't a data-to-sink injection trace — it's a **missing decision point** trace, per Lecture 2 Section 3. In `trace-authz.md`, build this table instead:

| Hop | Location | What is checked | What is *not* checked |
|---|---|---|---|
| 1 | … | … | … |
| Sink | … | … | … |

Then, directly beneath it:

1. Quote the **exact line** from `mark_paid` (the reviewed `main`-branch route) that performs the check `export_invoices` is missing, and explain in one sentence why that same pattern would close this gap.
2. `export_invoices` never reads `session["role"]` or `session["account_id"]` anywhere in its body. Grep the file (`grep -n "session\[" app.py`) and confirm this for yourself — paste the grep output for the whole file and mark which lines belong to `export_invoices`'s function body (there should be none, other than the initial `"user_id" not in session` check).

## Task 3 — Draw both traces as mermaid diagrams (20 min)

For each trace, produce a small `flowchart` diagram (see Lecture 2 for the shape) in `trace-diagrams.md`: boxes for source and sink, with the sanitizer-or-not decision made visible at the hop where it matters. Use red/highlighted styling (`style X fill:#7f1d1d,color:#fff`) on the box where the actual vulnerability lives, the way Lecture 2's diagrams do — this forces you to commit to *exactly one* hop as "where it went wrong," which is a useful test of whether your trace is precise or still fuzzy.

## Task 4 — The sanitizer-or-not test (10 min)

In `trace-injection.md`, apply Lecture 2 Section 6's test to three operations you can find **elsewhere** in `crunch-invoices` (not the ones already in the lecture's table):

1. `int(request.form["amount_cents"])` in `create_invoice` — real sanitizer against what, exactly? What would it *not* protect against?
2. `WHERE id = ? AND account_id = ?` in `get_invoice` — real sanitizer against what?
3. `session["role"]` compared inside `require_role(*roles)` — real sanitizer/control against what, and what does it *not* verify (hint: does it check anything about the specific object being acted on, the way `mark_paid`'s `account_id` filter does)?

## Done when…

- [ ] `trace-injection.md` has a complete, correctly-ordered hop table with no hop skipped, plus answers to all three prose questions.
- [ ] `trace-authz.md` has a complete hop table, the quoted comparison line from `mark_paid`, and the grep output proving `export_invoices` never reads role or account.
- [ ] `trace-diagrams.md` has two mermaid flowcharts, each with exactly one hop highlighted as the vulnerability's true location.
- [ ] Task 4's three sanitizer-or-not answers are specific about *which* danger each check does and doesn't address — not a blanket "yes it's safe" or "no it's not."

## Stretch

- Trace `status_filter` (the second parameter in `/invoices/search`) as fully as `term` — does the same hop (inside `build_search_query`) hold the vulnerability for both, or does `status_filter`'s path differ in any way?
- Pick one more route from `PR #482` you haven't traced yet (the download-link pair) and produce a hop table for **just** the `sig == expected` comparison — treat the comparison itself as the sink, per Lecture 2 Section 4.

## Submission

Commit `trace-injection.md`, `trace-authz.md`, and `trace-diagrams.md` to your portfolio under `c50-week-11/exercise-02/`. Exercise 3 turns these two traces into full, database-tracked findings.
