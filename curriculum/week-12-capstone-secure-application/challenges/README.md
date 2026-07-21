# Week 12 — Challenges

Two problems, meaningfully less hand-held than the exercises. Do them after all three exercises — both assume a Crunch Ledger that already has Exercise 1's threat model, Exercise 2's fixes, and Exercise 3's triaged findings database in place.

1. **[Challenge 1 — Remediate and re-test everything](challenge-01-capstone-remediate-and-retest.md)** — close every finding Exercise 3's triage query still shows as open, including the business-logic gap Lecture 3 previewed, and prove each one closed with a logged re-test. *(~2 hours.)*
2. **[Challenge 2 — Defend your design](challenge-02-capstone-defense-review.md)** — a structured design-defense review: answer a reviewer's questions about your threat model, your build, and your accepted risks, and produce a signed-off residual-risk statement. *(~90 min.)*

## How these are judged

Challenge 1 is closer to the exercises — every finding has a specific, provable fix, and you'll know you're right when your own re-test proves it. Challenge 2 is different in kind: there's no code to write, only reasoning to defend, and the skill being judged is whether your justifications hold up under real questioning rather than whether a test passes. Both are graded on:

- **Every finding closed, or explicitly and defensibly accepted** — an open `critical` or `high` finding with no justification is an incomplete capstone, full stop.
- **Evidence, not narrative** — Challenge 1 expects a re-test recorded in SQLite for every status change, the same discipline as every exercise this week and this course.
- **Reasoning that survives questioning** — Challenge 2 is not a formality; a design defense with hand-waved answers to "why did you accept this risk" is a failed defense, not a passed one.

Keep your work in `challenge-01/` and `challenge-02/` under this week's portfolio directory.
