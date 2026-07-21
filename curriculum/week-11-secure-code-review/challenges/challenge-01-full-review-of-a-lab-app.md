# Challenge 1 — Full Review of a Lab App

**Time:** ~90 minutes. **Difficulty:** Medium-hard. **No fixed finding count.**

## The scenario

Every exercise this week scoped you to `PR #482` — three new routes. Real reviews don't get that luxury: when you're the new reviewer on a codebase, or auditing a project before a compliance deadline, or picking up a legacy service nobody's looked at in a year, **the whole thing is in scope**, including the parts that were "already reviewed" and the parts that look boring enough that nobody thinks to check them again. This challenge is that review: all of `crunch-invoices`, `main` branch and `PR #482` both, using the complete four-step method from Lecture 1, with no per-route hints.

## Your task

Produce a single document, `challenge-01.md`, containing all four steps, run against the **entire** app:

### Step 1 — Entry-point table, every route

Every route in the file, `main` and `PR #482` combined — nine routes total. For each: method, every parameter and its source, and whether a login/role check is present (quote the line, or state plainly "no check found").

### Step 2 — Sink catalog, every dangerous operation

Every `execute(` call, every cryptographic operation, every place a decision-point check should exist. Don't limit this to the sinks already named in the lectures — read the whole file and build your own catalog from scratch, the way Lecture 1 Section 3 describes.

### Step 3 — Taint-trace every entry point against every sink it can reach

You've already done this for two flaws in Exercise 2. This step asks for the ones you **haven't** traced yet: at minimum, the three independent findings in the download-link routes (Lecture 2 Section 4 named them: the hardcoded key, the homemade MD5 MAC, the non-constant-time compare) — trace all three, even though Exercise 3 only asked you to write up one of them.

### Step 4 — Verify the five controls against the reviewed `main` branch too

This is the step most reviewers skip, and the reason this challenge exists: **run Lecture 1 Section 5's five-question checklist against `list_invoices`, `get_invoice`, `create_invoice`, and `mark_paid` — the routes that were supposedly already reviewed and clean.** For each, state explicitly which of the five questions it passes and *why* (quote the line that makes it pass), even though you expect no findings there. A review that only produces findings for new code and silently assumes old code is fine isn't a full review — it's a diff review wearing a full review's name tag. If you genuinely find all four clean, say so, with evidence, for each one.

## Deliverable

`challenge-01.md` with all four steps above, plus an updated `review_findings.db` (extending Exercise 3's) containing **every** finding from the whole app — the ones from `PR #482` you already wrote up, plus the new ones from the download-link routes, plus explicit "no finding, verified clean" notes (in the markdown, not the database — `review_findings` only holds real findings) for every `main`-branch route.

## Hints

<details>
<summary>On the download-link routes (Step 3)</summary>

Lecture 2 Section 4 already traced these three findings in full — hardcoded `SIGNING_KEY`, `hashlib.md5` used as a homemade MAC, and `sig == expected`. This challenge doesn't ask you to discover something the lecture didn't already show you; it asks you to write the **full seven-field finding** for the two the exercises didn't require (Exercise 3 only asked for one). Reread Lecture 2 Section 4 and Lecture 3 Section 2 before starting this step — the trace is done, the writing isn't.

</details>

<details>
<summary>On "verify the main branch too" (Step 4)</summary>

You're looking for a *negative* result here, and negative results still need evidence. For `get_invoice`, for example, a full answer looks like: "Passes the authorization question — the query is `WHERE id = ? AND account_id = ?` bound to `session[\"account_id\"]`, so a request for another account's invoice ID returns no row, confirmed by `curl -b cr-nina.txt http://127.0.0.1:5050/invoices/4` returning `404` even though invoice 4 exists (it belongs to `crunch-wholesale`)." That's a finding of "no finding," backed by a real request — not an assumption because the function is short.

</details>

## How success is judged

| Signal | Weak submission | Strong submission |
|---|---|---|
| Entry-point table | Only `PR #482`'s three new routes | All nine routes, `main` and PR combined |
| Sink catalog | Copied from the lectures | Built fresh by reading the whole file, includes sinks the lectures didn't name if any exist |
| Taint traces | Only the two from the exercises | Adds the two remaining crypto/secrets findings from the download-link routes |
| Control verification | Silent about `main`-branch routes | Explicitly checks all four, with quoted evidence, even though the expected result is "clean" |
| Database | Missing rows for the new findings | Every real finding from the whole app present, no duplicates, no merged independent findings |

## Submission

Commit `challenge-01.md` and the updated `review_findings.db` to your portfolio under `c50-week-11/challenge-01/`.
