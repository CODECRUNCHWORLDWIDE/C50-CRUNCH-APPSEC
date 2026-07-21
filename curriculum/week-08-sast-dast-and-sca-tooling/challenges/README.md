# Week 8 — Challenges

Two open-ended problems. Unlike the exercises, these have **no single right answer graded by row count** — the skill is judgment, precision, and writing a defensible argument. Do them after the three exercises.

1. **[Challenge 1 — Write a custom SAST rule](challenge-01-write-a-custom-sast-rule.md)** — find an app-specific vulnerable pattern generic rulesets miss, write a Semgrep rule for it, and prove it with a true-positive and a true-negative test case. *(~45 min.)*
2. **[Challenge 2 — Reconcile three scanners](challenge-02-reconcile-three-scanners.md)** — take your Exercise 3 backlog and merge findings that describe the same underlying weakness into one canonical entry, without accidentally merging genuinely distinct findings. *(~45 min.)*

## How these are judged

There's no answer key. Each challenge tells you what a *strong* submission looks like. You're being graded on:

- **Precision** — does your rule fire on exactly the pattern intended, and stay silent on the safe variant, proven by an actual test run rather than asserted?
- **The reconciliation judgment** — can you tell the difference between "the same bug, described twice" and "two different bugs that happen to share a keyword," and defend the distinction in writing?
- **Honesty about limits** — do you flag what you're not fully sure of (a rule that might have edge cases, a merge you're only 80% confident about) rather than presenting every call as obviously correct?

Keep your work in `challenge-01/` and `challenge-02/` under this week's portfolio directory. The reasoning is the point — a technically correct rule or merge with no explanation of *why* it's correct is an incomplete answer.
