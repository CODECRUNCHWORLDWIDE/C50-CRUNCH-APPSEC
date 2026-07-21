# Mini-Project — Harden a Login End to End

> Take `crunch-authlab` from its original broken state to a genuinely hardened login flow — argon2id password storage, rate limiting and lockout, working TOTP MFA, and secure session management — and prove every single fix against the original attack it closes. One app, four hardenings, one report that would survive a real security review.

**Estimated time:** 2.5–3 hours, best done Saturday after the exercises and both challenges.

This is the week's capstone, and it's cumulative by design: Exercises 1–3 and Challenge 1 already built every piece. The mini-project's job is to pull them into **one coherent app**, run **one clean end-to-end proof**, and write it up the way you'd hand it to a team lead — not as four separate homework answers, but as a single before/after story about one login flow.

---

## Deliverable

A directory in your portfolio `c50-week-04/mini-project/` containing:

1. `app_final.py` — the single, complete, hardened `crunch-authlab`: argon2id storage with lazy migration, per-account lockout + per-IP rate limiting, TOTP MFA with hashed recovery codes, and database-backed sessions with correct cookie flags, rotation, timeout, and real logout.
2. `schema_final.sql` — the complete schema (`users`, `login_events`, `recovery_codes`, `sessions` — no leftover `pending_sessions` hack from Exercise 2 unless you kept it deliberately; say so if you did).
3. `attack_suite.py` — **one script** that runs all four original attacks in sequence against a target `app.py`, printing pass/fail for each:
   - Dumps the `users` table and checks whether any row is plaintext or a fast unsalted hash.
   - Runs a shortened version of Challenge 1's stuffing combo list and reports how many succeeded.
   - Attempts to reach `/dashboard` with a forged, database-unbacked cookie (`session_id=admin-0000000000`).
   - Attempts to replay a session cookie captured before a `/logout` call.
4. `report.md` — the before/after story (structure below).
5. `notes.md` — a short reflection (see the end).

---

## Before you start: reset to v0

To make the "before" half of your proof honest, keep (or recreate) `app_v0.py` from Exercise 1 and its original `schema.sql` in a separate `before/` subfolder. `attack_suite.py` should be able to point at **either** `before/app_v0.py` (running on port 5000) or your final hardened app (also port 5000, run one at a time) and produce a report for whichever is currently running.

---

## Milestones

- **Milestone 1 (45 min):** Assemble `app_final.py` by merging Exercise 3's `app_v3.py` with Challenge 1's rate-limiting/lockout additions into one file. Run it, confirm login + MFA + logout all still work end to end for a real account.
- **Milestone 2 (45 min):** Write `attack_suite.py`. Run it against `before/app_v0.py` first — every check should report **VULNERABLE**. Paste that run into `report.md`'s "Before" section.
- **Milestone 3 (45 min):** Run `attack_suite.py` against `app_final.py`. Every check should now report **DEFENDED**. Paste that run into `report.md`'s "After" section. If anything still reports vulnerable, fix it before moving on — a mini-project that ships with a known-open hole isn't done.
- **Milestone 4 (30–45 min):** Write the rest of `report.md` (structure below) and `notes.md`.

---

## `report.md` structure

```markdown
# crunch-authlab — Before/After Security Report

## Summary
One paragraph: what was broken, what you fixed, and the one-line proof that it worked.

## Before — attack_suite.py against app_v0.py
[paste the full run output]

## After — attack_suite.py against app_final.py
[paste the full run output]

## Fix-by-fix breakdown
For each of the four hardenings, one short section with:
- The original vulnerability (link back to the lecture/exercise that introduced it)
- The specific attack that exploited it
- The specific fix (name the function/technique, e.g. "argon2id via argon2-cffi", "SameSite=Lax + HttpOnly + rotation on login")
- The exact line(s) of attack_suite.py output that prove it's closed

## What's still out of scope
Honestly list anything NOT covered by this hardening (e.g., no WebAuthn, no distributed rate limiting across multiple app instances, no email-based account recovery flow reviewed). A real report names its boundaries.
```

---

## Rules

- **Every claim needs a pasted command and its actual output.** "Argon2id is now used" without a `SELECT password_hash FROM users` showing `$argon2id$…` is an assertion, not a proof.
- **The same `attack_suite.py` must run against both versions.** Don't write one script that only knows how to fail against `app_v0.py` and a different one that only knows how to pass against `app_final.py` — that's grading your own homework.
- **Auth events must be logged to the database for every attempt in every script**, success or failure — this is the standing course rule (SQL/Python for any findings, logs, or telemetry, never a spreadsheet) and it's also what makes Challenge 1's detection queries meaningful against the final version.
- **No plaintext secrets committed.** Regenerate TOTP secrets and recovery codes for whatever demo accounts end up in your committed `schema_final.sql`, or seed the demo data via a script that runs the real hashing/enrollment functions instead of hardcoding hashes.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| All four hardenings present and working | 35% | Password storage, rate-limit/lockout, TOTP MFA, and session security all live in one `app_final.py`, verified by hand |
| `attack_suite.py` correctness | 25% | Same script, two runs, correctly reports vulnerable-then-defended for all four checks |
| Report quality | 20% | `report.md` reads like a real before/after security report a reviewer could act on |
| Honesty about scope | 10% | "What's still out of scope" is specific, not a throwaway line |
| Auth event logging | 10% | Every attempt across every script lands a row in `login_events`, queryable |

---

## Reflection (`notes.md`, ~200 words)

1. Which of the four hardenings took the longest to get right, and why?
2. Where did proving a fix (not just writing it) catch a bug you didn't know you had?
3. If you had one more week on just this app, what would you build next — WebAuthn, distributed rate limiting, anomaly-based session detection? Why that one?
4. How does this week's "build it broken, then fix it" method compare to Weeks 1–3's "attack something pre-built"? Which taught you more, and why might a real team use both approaches at different times?

---

## Why this matters

Every one of the OWASP Top 10's A07 (Identification and Authentication Failures) findings you'll see in a real audit is one of these four categories, in some app you didn't write, under time pressure, without a lecture telling you what to look for. Doing the full loop — break it, prove it's broken, fix it, prove it's fixed, write it up — on code you wrote yourself is the closest this course gets to that real experience before Week 11's secure code review and Week 12's capstone.

When done: push, then take the [quiz](../quiz.md) and start [Week 5 — Injection & input validation](../../week-05-injection-and-input-validation/).
