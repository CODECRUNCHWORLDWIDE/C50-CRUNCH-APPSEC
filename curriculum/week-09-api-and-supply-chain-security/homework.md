# Week 9 — Homework

Five problems, ~5 hours total, spread across the week. All work runs against `crunch-tasks-api` on `127.0.0.1` or local, offline package indexes — nothing here ever points at a system or a registry you don't own. Commit each.

---

## Problem 1 — Map every API Top 10 category to its web Top 10 cousin (45 min)

Lecture 1 argued that BOLA is "IDOR wearing an API's clothes" and BFLA mirrors Week 3's missing function-level access control. In `api-vs-web-top10.md`, for each of the five categories this week covered:

1. Name the closest web-Top-10 equivalent from Week 3 (if one exists — one of the five genuinely doesn't have a close web-Top-10 cousin; name which one, and explain why the API context makes it its own category).
2. Write two or three sentences on what changed (the transport, the trust signal, the typical fix) and what stayed the same (the underlying missing check).

**Deliver** `api-vs-web-top10.md`, five short sections.

---

## Problem 2 — Extend `crunch-tasks-api` with a new endpoint, then break and fix it (75 min)

Add a new route: `POST /api/v1/tasks` to create a task for the calling user. Build it with **one deliberate flaw** from this week's five categories (state clearly, in a comment, which category and why), then fix it exactly like every other route in the app.

1. Write the route. Deliberately introduce one flaw.
2. Demonstrate it with a `curl` command.
3. Fix it at the source.
4. Re-test in both directions.
5. Log it as a new row in your `api_findings` table from Challenge 1.

**Deliver** your updated `app.py`, the demonstrate/re-test evidence, and confirmation the new row is in your findings database.

---

## Problem 3 — Read a real API breach writeup and map it to a category (60 min)

Find one publicly reported, real API security incident or bug-bounty writeup (search "API BOLA bug bounty writeup" or similar — HackerOne and Bugcrowd both publish disclosed reports, and several security vendors publish free API breach case studies).

In `api-breach-writeup.md`:

1. The source, the affected service (if named), and a two-to-three-sentence plain-English summary (you may quote **at most one short phrase** directly from the source, in quotes, cited).
2. Which of this week's five categories it belongs to, and why.
3. What you'd guess the fix looked like, reasoning from the category — not by finding the actual patch.

**Deliver** `api-breach-writeup.md`.

---

## Problem 4 — Generate and diff two SBOMs (60 min)

Using your `crunch-tasks-api` virtual environment, deliberately install one additional package you don't currently use — pick something small and genuinely useful, like `python-dotenv` — then:

1. Regenerate the SBOM: `pip-audit -r requirements.txt --format=cyclonedx-json -o sbom-v2.json` (after re-freezing `requirements.txt`).
2. Diff `sbom.json` (from Exercise 3) against `sbom-v2.json` and, in `sbom-diff.md`, list exactly which components were added.
3. Run `pip-audit` against the new `requirements.txt` and confirm whether the new package (or anything it pulled in transitively) introduces a new advisory.
4. One paragraph: if your organization required an SBOM diff review before every dependency-adding pull request merged, what would that have caught here, and what would it not have caught (hint: think about Lecture 3's compromised-package scenario — a diff review catches a *new* name appearing, but what about a version bump of something already approved)?

**Deliver** `sbom-diff.md`, `sbom-v2.json`.

---

## Problem 5 — Write a rate-limit and role-check policy document (60 min)

`crunch-tasks-api` now has a rate limiter (Challenge 1) and role checks (Exercise 1/Challenge 1). Write `api-policy.md`, a one-page policy a real engineering team could adopt, covering:

1. **Rate limiting:** which endpoints get the tightest limits and why (hint: think about which endpoints are unauthenticated, or authenticate a *new* identity per request, versus which ones already require a valid, revocable token).
2. **Role checks:** a table of every route in `crunch-tasks-api`, the role(s) allowed to call it, and whether the check is currently enforced (it all should be, after Challenge 1 — this table is your proof, not new work).
3. One paragraph on what should happen when a *new* route gets added six months from now — what would force the next developer to explicitly declare its rate limit and its role requirement, rather than silently defaulting to "unlimited, any authenticated user" the way every original flaw in this app did.

**Deliver** `api-policy.md`.

---

## Time budget

| Problem | Time |
|--------:|----:|
| 1 | 45 min |
| 2 | 75 min |
| 3 | 60 min |
| 4 | 60 min |
| 5 | 60 min |
| **Total** | **~5 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
