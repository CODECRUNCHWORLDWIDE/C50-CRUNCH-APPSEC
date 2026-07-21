# Week 9 — Challenges

Two open-ended problems. Unlike the exercises, these have **far less step-by-step guidance** — the skill being tested is recognizing a category and designing a fix, not following a numbered recipe. Do them after the three exercises.

1. **[Challenge 1 — Harden a lab API end to end](challenge-01-harden-a-lab-api.md)** — close out every remaining flaw in `crunch-tasks-api` (BFLA, excessive data exposure, missing rate limiting), applying Lecture 2's design disciplines rather than one-off patches. *(~2h.)*
2. **[Challenge 2 — Simulate a dependency attack](challenge-02-simulate-a-dependency-attack.md)** — build your own local, offline dependency-confusion scenario from scratch, then prove that hash-pinning stops it. *(~90 min.)*

## How these are judged

There's no single answer key with exact line counts. You're being judged on:

- **Correct category attribution** — did you name the *right* API Top 10 category for each flaw you found, and can you defend it against Lecture 1's definitions?
- **Real evidence** — an actual request/response, or a real terminal transcript, not "I think this would work."
- **Complete records** — every API finding you log has, at minimum, a category, an endpoint, a likelihood/impact score with justification, and demonstration evidence; every dependency finding has a package, version, and advisory ID.
- **Honest status** — a finding you didn't actually fix stays `status = 'open'`; don't mark something fixed you didn't re-test.

Challenge 1 writes into the **same** `dependency-findings.db`-style discipline as Exercise 3 (extend it with an `api_findings` table rather than starting a new database). Challenge 2 is entirely local and offline — don't touch a real package registry.
