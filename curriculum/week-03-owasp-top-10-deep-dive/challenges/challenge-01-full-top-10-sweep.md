# Challenge 1 — Full Top 10 Sweep of One App

**Target:** OWASP Juice Shop, running in your Week 1 isolated lab at `http://127.0.0.1:3000`.

**Estimated time:** ~2 hours.

Everything you've fixed so far this week was in `crunch-notes` — an app whose source you own and can edit. Juice Shop is different: it's a **black box** to you. You can observe it, poke at it, and read its responses, but you can't open its source and add an `AND user_id = ?` clause. This challenge is about **recognition and evidence** — proving a category is present and explaining, in prose, what the fix *would* be — not applying a patch to a vendor's container image.

Juice Shop was purpose-built by OWASP as a training target, so representative flaws from most Top 10 categories are genuinely present and reachable through normal browsing and request tampering, with no exploit tooling beyond your browser, its dev tools, and `curl`.

## Goal

Find and log a representative finding for **at least six** of the ten categories. Getting all ten is a stretch goal, not a requirement — some categories are considerably harder to spot from the outside than others, and part of the skill this challenge tests is knowing which ones you can actually verify as a black-box observer versus which ones you'd need source access to confirm.

## Rules

- Stay inside your isolated lab. Juice Shop at `127.0.0.1:3000` only.
- No automated scanners this week (Week 8 introduces those properly, with the judgment to interpret their output). Everything here is manual: browser, dev tools Network tab, `curl`.
- For every finding: log it to the **same** `findings.db` from Exercise 3, with `asset` starting `"Juice Shop"` so it's distinguishable from your `crunch-notes` findings.
- Since you can't patch a vendor image, leave `remediated_at`/`retested_at` `NULL` and `status = 'open'` for every row here — but fill `remediation_summary` with the fix you *would* make if you owned this code, in enough specific detail that another engineer could implement it from your description alone.

## Where to look, by category (hints, not steps)

Deliberately not a click-by-click walkthrough — Lecture 1–3 already gave you that once each. Use what those lectures taught you to *recognize* these, the same way you'd approach an app you'd never seen a course-written walkthrough for.

- **A01 Broken Access Control** — Juice Shop has more than one object a logged-in user shouldn't be able to reach that belongs to someone else. Look at what happens to basket-related and order-related endpoints when you change a numeric ID in the URL or request body while authenticated as a low-privilege account.
- **A02 Cryptographic Failures** — check how the app handles a password reset "security question" flow, and think about what makes a security question a weak secret in the first place (hint: it's not a hashing algorithm problem this time).
- **A03 Injection** — the login form and the product search box are both worth trying a single `'` character in, then reading how the app responds differently to a syntactically valid vs. invalid quote.
- **A04 Insecure Design** — look for a business-logic path that lets you do something no legitimate user flow should ever allow, regardless of how carefully each individual step was coded (a classic shape: applying the same discount code an unlimited number of times).
- **A05 Security Misconfiguration** — `curl -I` the site, check `robots.txt`, and look for a directory that shouldn't be listable.
- **A06 Vulnerable and Outdated Components** — the app names its own tech stack and version somewhere in the page source or an about/score-board style page; cross-reference what you find against a public advisory database.
- **A07 Identification and Authentication Failures** — try the login form with a wrong password several times in a row and observe whether anything changes about the app's behavior or response timing.
- **A09 Security Logging and Monitoring Failures** — this one you can't fully verify from outside (you can't see Juice Shop's server-side logs), but you *can* reason about it: after triggering an obvious attack (like your A03 finding above), is there any user-visible sign the app noticed? Write your reasoning, not a definitive verdict, and say plainly that this is an inference, not direct evidence.
- **A08 and A10** are the hardest to find as a pure black box in this specific app — if you find genuine, defensible evidence for either, log it; if not, explain in `sweep-notes.md` what *would* need to be true about the app's internals for each to be present, and why external observation alone can't confirm or rule it out.

## Deliverable

`sweep-notes.md` containing, for each category you found:

1. The category and a one-sentence description of the specific flaw.
2. The request/response (or screenshot description) that proves it.
3. Your risk score (likelihood × impact) with justification.
4. The fix you'd make if you owned the code.

Plus your rows loaded into `findings.db`.

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Coverage | 30% | At least 6 categories found with real, specific evidence |
| Correct attribution | 25% | Each finding is filed under the right OWASP category, defensibly |
| Evidence quality | 20% | Actual requests/responses, not descriptions of "trying things" |
| Remediation specificity | 15% | Fix descriptions are concrete enough to implement, not "add validation" |
| Honest gaps | 10% | Categories you couldn't confirm are marked as such, with reasoning, not silently skipped |

## Submission

Commit `sweep-notes.md` and your updated `findings.db` (now containing your `crunch-notes` rows from Exercise 3 plus your Juice Shop rows from this challenge) to your portfolio under `c50-week-03/challenge-01/`.
