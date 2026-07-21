# Week 5 — Challenges

Two problems, less hand-holding than the exercises. Do them after all three exercises — both assume every fix from Exercises 1–3 is already in place.

1. **[Challenge 1 — Convert an injectable app](challenge-01-convert-an-injectable-app.md)** — take the whole Crunch Notes codebase and eliminate every remaining injection flaw in one pass, end to end. *(~2h.)*
2. **[Challenge 2 — Blind injection detection & defense](challenge-02-blind-injection-defense.md)** — exploit VULN #5 and #6 without any error message or data ever being shown to you, then build a detector from query logs. *(~90 min.)*

## How these are judged

There's no single answer key for either — both have "expected result" sections instead of exact-match grading. You're being judged on:

- **Completeness** — Challenge 1 in particular: did you find and fix *every* remaining flaw, or just the ones that were easy to spot?
- **Correctness of the fix, not just "it looks different now"** — a fix that happens to block your one test payload but isn't structurally correct (see Lecture 2 Section 4) doesn't count.
- **The detection half of Challenge 2** — this course's attacker/defender habit applies here specifically: exploiting blind injection without also building a way to notice it happening is only half the assignment.

Keep your work under `c50-week-05/challenge-01/` and `c50-week-05/challenge-02/` in your portfolio.
