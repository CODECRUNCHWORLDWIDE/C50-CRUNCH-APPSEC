# Week 6 — Challenges

Two problems, meaningfully less hand-held than the exercises. Do them after all three exercises — both assume a `crunch-helpdesk` that already has Exercise 1's IDOR fix, Exercise 2's RBAC decorator, and Exercise 3's test matrix in place.

1. **[Challenge 1 — Close a privilege-escalation path](challenge-01-close-privilege-escalation.md)** — a new route ships with a subtler vertical-escalation bug than anything in the lectures. Find it by reading, not by being told where it is. *(~90 min.)*
2. **[Challenge 2 — Enforce multi-tenant isolation](challenge-02-multi-tenant-isolation.md)** — prove, systematically, that zero cross-tenant leakage exists across *every* route in the app, not just the ones already covered. *(~90 min.)*

## How these are judged

Challenge 1 has a specific bug with a specific fix — you'll know you're right when your own test proves it. Challenge 2 is closer to an open audit — the skill being judged is thoroughness and the discipline to check systematically rather than spot-check. Both are graded on:

- **Finding it yourself** — the bug in Challenge 1 is not marked with a `# VULNERABLE` comment. Use the four-question checklist from Lecture 3, Section 5, not a guess.
- **The right fix, not just a fix** — a fix that happens to block the one exploit you tried, but doesn't match the actual policy (Lecture 1's permission table, the tenant rule), is an incomplete answer.
- **Evidence, not narrative** — both challenges expect a re-test recorded in SQLite, the same discipline as the exercises, not a sentence claiming "I fixed it."

Keep your work in `challenge-01/` and `challenge-02/` under this week's portfolio directory.
