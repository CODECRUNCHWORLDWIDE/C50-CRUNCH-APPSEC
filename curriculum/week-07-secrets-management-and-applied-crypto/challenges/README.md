# Week 7 — Challenges

Two problems, both with less hand-holding than the exercises. Do them after all three exercises. Challenge 1 has a concrete right answer (the feature must actually work and actually be secure); Challenge 2 is a design/judgment exercise with no single correct layout, graded the way Week 1's challenges were.

1. **[Challenge 1 — Fix a broken-crypto feature](challenge-01-fix-a-broken-crypto-feature.md)** — a password-reset-token feature stacking weak RNG on top of the homemade XOR cipher, fixed end-to-end with far less guidance than Exercises 1–3 gave you. *(~2h.)*
2. **[Challenge 2 — Design a secrets workflow](challenge-02-design-a-secrets-workflow.md)** — design and implement a small but real dev → CI → production secrets pipeline with a rotation plan, for a hypothetical 3-service team. *(~2h.)*

## How these are judged

- **Challenge 1** has an answer key of sorts: the reset token must be generated with a CSPRNG, must not be guessable or reusable, and the "encrypted" storage must be an authenticated primitive — you're graded on whether the fixed feature actually resists the attacks it used to be vulnerable to, which you'll prove by trying them.
- **Challenge 2** has no single correct architecture. You're graded on:
  - **Completeness** — does the design cover local dev, CI, and production, with no environment left implicitly "figure it out later"?
  - **A real rotation plan** — not "rotate secrets periodically" but *who* rotates *what*, *how often*, and *what breaks* during cutover if you get it wrong.
  - **Honesty about tradeoffs** — every real secrets architecture has a weak point (a break-glass procedure, a bootstrapping secret, an operator with too much access); name yours instead of pretending the design has none.

Keep your work in `challenge-01/` and `challenge-02.md` under this week's portfolio folder.
