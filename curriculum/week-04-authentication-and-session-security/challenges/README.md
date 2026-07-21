# Week 4 — Challenges

Two open-ended problems. Unlike the exercises, these have **no single right answer** — the skill is judgment and completeness, not recall. Do them after all three exercises.

1. **[Challenge 1 — Defend against credential stuffing](challenge-01-defend-credential-stuffing.md)** — write your own stuffing script, watch it succeed against undefended `crunch-authlab`, then design and prove a rate-limit + lockout defense against it. *(~90 min.)*
2. **[Challenge 2 — Audit a full login flow](challenge-02-audit-a-login-flow.md)** — given the source of a different, unfamiliar login flow, find every authentication and session flaw in it unguided, and write it up like a real finding. *(~90 min.)*

## How these are judged

There's no answer key with exact output to match. Instead, each challenge tells you what a *strong* submission looks like. You're being graded on:

- **Completeness** — did you find (or defend against) the real issues, not just the obvious one?
- **Proof, not assertion** — every claimed vulnerability or fix is backed by a command you ran and its actual output, not "this would probably work."
- **Attacker/defender pairing** — every flaw you name comes with a stated detection method and a stated fix, the Week 1 habit this whole course drills.

Keep your work in `challenge-01.md` / `challenge-02.md` with your commands, output, and reasoning together. The reasoning is the point.
