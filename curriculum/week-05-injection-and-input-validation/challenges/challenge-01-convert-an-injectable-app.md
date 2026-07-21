# Challenge 1 — Convert an Injectable App

**Goal:** Take your Crunch Notes codebase — with VULN #1, #2 (SQLi half), #3, and #4 already fixed from the exercises — and finish the job: convert **every** remaining string-built query to parameterized SQL, and close **every** remaining XSS gap, in one deliberate pass across the whole file.

**Estimated time:** ~2 hours.

Real code review doesn't come with a numbered list telling you which lines are broken. This challenge removes some of that scaffolding on purpose: you're given the file and the rule ("no string-built SQL, no unescaped output"), not a route-by-route checklist.

## What's still broken, going in

If you've completed Exercises 1–3 including their stretch goals, only VULN #5 and #6 (blind SQLi) remain — save those for Challenge 2, they need a different technique. If you skipped any stretch goals, this challenge is where you close them:

- VULN #2's reflected XSS half (`{{ q|safe }}` in `/search`), if not already fixed in Exercise 3's stretch.
- VULN #7's DOM XSS (`innerHTML` in `/welcome`), if not already fixed in Exercise 3's stretch.

## Task 1 — Full-file audit

Read through the **entire** `app.py`, top to bottom, one more time, specifically hunting for these two patterns — the same review habit Week 11 formalizes:

1. Any f-string, `.format()`, `%`-formatting, or `+` concatenation that builds a string later passed to `db.execute(...)`.
2. Any Jinja2 template variable rendered with `|safe`, and any client-side JavaScript writing a variable into `innerHTML`, `outerHTML`, or calling `document.write()`.

Write your findings — even ones you already fixed in earlier exercises — into `audit-notes.md` as a checklist. This file is your evidence that the pass was systematic, not lucky.

## Task 2 — Fix everything on the list

Apply the exact rules from Lectures 2 and 3:

- Every remaining SQL string becomes a parameterized query with `?` placeholders and a separate tuple of bound values.
- Every remaining `|safe` is removed (or, if the note genuinely needs to allow some HTML in a future version, swapped for a `bleach.clean()` call with an explicit allowlist — document that decision in `audit-notes.md` if you go this route, since Crunch Notes doesn't currently require it).
- Every remaining DOM sink (`innerHTML`, `document.write`) writing untrusted data becomes `textContent` or an equivalent that doesn't parse its argument as markup.

## Task 3 — Full payload-library sweep

Extend `findings.db`'s `payload_library` with at least **2 new payloads per category** (sqli, xss) beyond what Exercises 1–3 already recorded — different techniques, not just character-case variants of the same one. Run **all** payloads in the library against **every** route that touches user input (`/login`, `/search`, `/notes`, `/notes/new`, `/diagnostics/ping`, `/welcome`), not just the route each payload was originally written for — a payload written for one endpoint sometimes reveals a second endpoint is broken too.

## Expected result

- `SELECT * FROM verifications WHERE result = 'allowed'` returns zero rows across the **entire** payload library run against the **entire** app (excluding VULN #5/#6, Challenge 2's job).
- `grep -n "f\"" app.py` (or your editor's search) turns up no f-string that's later passed to `db.execute()`.
- `grep -n "|safe" app.py` turns up zero results, OR every remaining instance is documented in `audit-notes.md` with a `bleach.clean()`-based justification.
- `grep -n "innerHTML" app.py` (inside the `WELCOME_HTML` script block) turns up zero results.

## Rubric

| Criterion | What "strong" looks like |
|---|---|
| Completeness | Every string-built query and every `|safe`/`innerHTML` instance found and fixed, not just the ones from the exercises |
| Correctness | Fixes are structurally correct (parameterized, not escaped-by-hand; encoded, not blocklisted) |
| Verification | Full payload-library sweep across every route, recorded in `verifications`, zero `allowed` rows |
| Audit trail | `audit-notes.md` reads like something you could hand to a teammate reviewing your PR |

## Submission

Commit the fully converted `app.py`, `audit-notes.md`, and the updated `findings.db` to `c50-week-05/challenge-01/`.
