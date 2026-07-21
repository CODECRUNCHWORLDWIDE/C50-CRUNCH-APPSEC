# Week 3 — Challenges

Two open-ended problems. Unlike the exercises, these have **far less step-by-step guidance** — the skill being tested is recognizing a category from the pattern, not following a numbered recipe. Do them after the three exercises.

1. **[Challenge 1 — Full Top 10 sweep of one app](challenge-01-full-top-10-sweep.md)** — sweep OWASP Juice Shop (your Week 1 lab target) for a representative flaw from as many of the ten categories as you can find, and log each one to `findings.db`. *(~2h.)*
2. **[Challenge 2 — Remediate and re-test three flaws](challenge-02-remediate-and-retest.md)** — go back to `crunch-notes` and fix three flaws from Lectures 2–3 that Exercises 1–2 didn't already hand-fix for you, then re-test and update `findings.db`. *(~90 min.)*

## How these are judged

There's no single answer key with exact row counts. You're being judged on:

- **Correct category attribution** — did you name the *right* OWASP category for each flaw you found, and can you defend it against Lecture 1–3's definitions?
- **Real evidence** — an actual request/response or a specific reproduction step, not "I think this is vulnerable."
- **Complete records** — every finding you log has, at minimum, a category, an asset, a likelihood/impact score with justification, and demonstration evidence.
- **Honest status** — a finding you didn't actually fix stays `status = 'open'`; don't mark something `remediated` you didn't re-test.

Both challenges write into the **same** `findings.db` schema from Exercise 3. Don't create a second database — the whole point of a findings store is that everything lives in one queryable place.
