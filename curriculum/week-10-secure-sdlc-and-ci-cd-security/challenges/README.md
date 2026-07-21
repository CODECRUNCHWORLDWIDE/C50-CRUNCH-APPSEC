# Week 10 — Challenges

Two problems, less hand-holding than the exercises. Do them after all three exercises — both assume every fix from Exercises 1–3 is already in place.

1. **[Challenge 1 — Design a secure pipeline](challenge-01-design-a-secure-pipeline.md)** — design, from scratch and unassisted, a secure CI/CD pipeline for a new hypothetical service, mapping SDLC activities to concrete controls. *(~2h.)*
2. **[Challenge 2 — Attack and defend a lab pipeline](challenge-02-attack-and-defend-a-pipeline.md)** — exploit a context-expression shell-injection hole in your own local pipeline via `act`, then patch it and build a detector for the pattern. *(~90 min.)*

## How these are judged

There's no single answer key for either — both have "expected result" sections instead of exact-match grading. You're being judged on:

- **Completeness** — Challenge 1 in particular: did your design cover every SDLC phase and every hardening category from Lectures 1–3, or just the obvious ones?
- **Correctness of the fix, not just "it looks different now"** — Challenge 2's patch has to close the actual injection vector (Lecture 2 Section 5), not just happen to block your one test payload.
- **The detection half of Challenge 2** — this course's attacker/defender habit applies here specifically: exploiting the injection without also building a way to notice it happening is only half the assignment.

Keep your work under `c50-week-10/challenge-01/` and `c50-week-10/challenge-02/` in your portfolio.
