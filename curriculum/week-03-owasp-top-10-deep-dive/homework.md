# Week 3 — Homework

Five problems, ~5 hours total, spread across the week. All work runs against `crunch-notes` on `127.0.0.1` or your Week 1 lab targets — nothing here ever points at a system you don't own. Commit each.

---

## Problem 1 — Map every OWASP category to a CWE (45 min)

The OWASP Top 10 sits on top of the more granular CWE (Common Weakness Enumeration) taxonomy — each Top 10 category groups several specific CWEs. In `cwe-mapping.md`, for **each** of the ten categories, look up (via the OWASP Top 10 pages linked in `resources.md`) and record:

1. The category name and number (e.g., `A03:2021-Injection`).
2. At least **two** specific CWE IDs it groups (e.g., CWE-89 SQL Injection, CWE-78 OS Command Injection).
3. One sentence on what those two CWEs have in common that justifies grouping them under the same Top 10 category.

**Deliver** `cwe-mapping.md`, ten short sections.

---

## Problem 2 — Rank last year's list against this course's ordering (45 min)

The Top 10 list changes between editions (Lecture 1, Section 2). Compare the 2017 and 2021 orderings (both linked in `resources.md`).

1. Name one category that moved up significantly between 2017 and 2021, and one that moved down.
2. For each, write two or three sentences hypothesizing *why*, using Lecture 1's methodology explanation (incidence rate vs. community survey weighting) — you're reasoning from the method, not guessing randomly.
3. Name the one category that's genuinely new in 2021 with no 2017 equivalent, and explain in your own words why it needed to become its own category rather than living inside an existing one.

**Deliver** `list-evolution.md`.

---

## Problem 3 — Write the missing input validation (60 min)

None of `/login`, `/search`, or `/avatar` validate their inputs before using them (beyond the specific fixes Lectures 2–3 already applied to the security-critical part of each). Add basic input validation to all three:

1. `/login` — reject empty `username`/`password` with a clean 400 instead of letting an empty string reach the database query.
2. `/search` — cap `q` at a reasonable maximum length (e.g., 200 characters) and reject non-string input.
3. `/avatar` — beyond Lecture 3's allowlist fix, reject a missing or empty `url` parameter with a 400 instead of letting `requests.get(None)` raise an unhandled exception.

**Deliver** `input-validation.diff` (or your updated `app.py` plus a short note listing exactly what you added) and three `curl` commands proving each validation trips correctly.

---

## Problem 4 — Read a real CVE and map it to a category (60 min)

Pick any one publicly disclosed CVE for a real, well-known open-source web framework or library (search the National Vulnerability Database, linked in `resources.md`, for something described in plain enough language to follow — SQL injection, broken auth, and deserialization CVEs tend to be the most readable for a first pass).

In `cve-writeup.md`:

1. The CVE ID, the affected software and version range, and a two-to-three-sentence plain-English summary of the flaw (you may quote **at most one short phrase** directly from the advisory — put it in quotes and cite the source).
2. Which OWASP Top 10 category it belongs to, and why.
3. What you'd guess the one-line fix looked like, based on the category (you don't need to find the actual patch — reason from the pattern).

**Deliver** `cve-writeup.md`.

---

## Problem 5 — Extend `crunch-notes` with a new, deliberately flawed feature, then fix it (90 min)

Add one new route to `crunch-notes` — e.g., a `POST /notes` route to create a note, or a `POST /notes/<id>/share` route to share a note with another username. Build it with **one deliberate flaw** from any category this week covered, then fix it, exactly like every route already in the app.

1. Write the route. Deliberately introduce one flaw (state clearly, in a comment, which category and why).
2. Demonstrate it with a `curl` command.
3. Fix it at the source.
4. Re-test in both directions.
5. Log it as an eleventh row in your `findings.db` from Exercise 3.

**Deliver** your updated `app.py`, the demonstrate/re-test evidence, and confirmation the new row is in `findings.db`.

---

## Time budget

| Problem | Time |
|--------:|----:|
| 1 | 45 min |
| 2 | 45 min |
| 3 | 60 min |
| 4 | 60 min |
| 5 | 90 min |
| **Total** | **~5 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
