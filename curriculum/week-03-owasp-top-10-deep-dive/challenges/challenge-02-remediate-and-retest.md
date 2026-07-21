# Challenge 2 — Remediate and Re-Test Three Flaws

**Estimated time:** ~90 minutes.

Exercises 1 and 2 walked you through fixing three of `crunch-notes`'s ten flaws (the IDOR, the missing role check, and the misconfiguration) with the exact code from the lectures right there to copy. This challenge removes that scaffolding: **pick any three of the seven remaining flaws** and fix them yourself, from your own understanding of Lecture 2 and Lecture 3, not by re-reading the lecture's fix line by line while you type.

## The seven candidates

Choose **three**. All are covered, with worked fixes, in Lecture 2 or Lecture 3 — the challenge is applying the pattern to your own copy of `app.py` without the answer already pasted in front of you, and being able to explain your fix in your own words.

| Category | Flaw | Where |
|---|---|---|
| A02 | MD5, unsalted password hashing | `md5()`, `/login` |
| A02 | Hardcoded `SECRET_KEY` | `app.config["SECRET_KEY"]` |
| A03 | SQL injection via string-built query | `/search` |
| A04 | No size/pagination limit designed in | `/notes/export`, `notes` schema |
| A06 | Outdated, vulnerable pinned dependencies | `requirements.txt` |
| A07 | No brute-force lockout on login | `/login` |
| A08 | Insecure deserialization with `pickle` | `/admin/install-plugin` |

(A10 SSRF is deliberately left off this list — Lecture 3 already gave it a full demonstrate/fix pass and Exercises 1–2 covered the same depth of independent practice for A01/A05; pick your three from the seven above.)

## Rules

- **No pasting the lecture's fix verbatim without understanding it.** Read the relevant lecture section once, close it, then write the fix from what you understood. Re-open the lecture only to check your work afterward.
- Every one of your three flaws must go through the **full cycle**: demonstrate (if you haven't already from following along in the lecture, re-demonstrate it now against your own current `app.py`), remediate, re-test, and get logged into `findings.db` with `status = 'remediated'` and a real `retest_result`.
- Re-test **both directions** for each — the attack must now fail, and the legitimate use case must still work (Exercise 1's IDOR fix taught you why this matters: a fix that also breaks the legitimate case isn't done).

## What "in your own words" means for the write-up

For each of your three, `remediation-notes.md` should answer:

1. What specifically was wrong — not "it was insecure" but the precise mechanism (e.g., "the query concatenated `q` directly into the SQL string, so a `'` in the input closed the intended string literal early").
2. What you changed, and why that specific change closes the gap (not just "I fixed it").
3. What you'd tell a teammate to watch for so they don't reintroduce this same pattern somewhere else in the app.

## Expected result (spot checks)

- Your three chosen flaws' re-test commands each produce the "attack now fails, legitimate use still works" pattern from Exercise 1's Task 6.
- `findings.db` has three new rows (or three updated rows if you'd already logged them as `open` from following the lecture) with `status = 'remediated'`, real timestamps, and `retest_result = 'pass'`.
- `remediation-notes.md` explains the mechanism, not just the symptom, for all three.

## Done when…

- [ ] Three flaws chosen, demonstrated against your own running `crunch-notes`, remediated, and re-tested in both directions.
- [ ] `findings.db` reflects all three as `remediated` with `retest_result = 'pass'`.
- [ ] `remediation-notes.md` explains the mechanism (not the symptom) for each of your three.
- [ ] You did not simply retype the lecture's fix without first attempting your own version.

## Stretch

- Pick a fourth, and this time write the fix **before** re-reading the lecture section at all — only check afterward. Note in `remediation-notes.md` whether your independent fix matched the lecture's approach, and if it differed, whether yours was better, worse, or just different.

## Submission

Commit `remediation-notes.md`, your updated `app.py`, and your updated `findings.db` to your portfolio under `c50-week-03/challenge-02/`.
