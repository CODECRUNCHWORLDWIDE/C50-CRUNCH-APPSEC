# Challenge 1 — Design a Secure Pipeline

**Goal:** Design, from scratch and with far less hand-holding than the exercises, a secure CI/CD pipeline for a new hypothetical service — mapping SDLC security activities to concrete controls and producing a real (if unrun) workflow file, not just a diagram.

**Estimated time:** ~2 hours.

## The scenario

A small team is building **Crunch Ledger**, a new internal service that records completed course certifications (tying back to this course's own completion/certificate flow) into a database. It will:

- Accept HTTP requests from the main course platform to record a completion.
- Read from and write to its own database.
- Deploy via a CI/CD pipeline, same as Crunch Deploy this week, on push to `main`.
- Never be exposed directly to the public internet — only the course platform's backend talks to it.

You have **no starter code** this time — this challenge is a design exercise, not a break-then-fix one. Everything you produce is unrun, reviewed on paper (or in `act`, if you choose to sketch a skeleton workflow and try it), which is exactly how a real design review works before a single line of the pipeline exists.

## Task 1 — Map security activities to every SDLC phase

In `sdlc-map.md`, produce a table — one row per phase (requirements, design, build, test, deploy, operate) — naming:

- The specific security activity for Crunch Ledger at that phase (not a generic textbook answer — tie it to what this specific service does: it writes financial-adjacent-but-not-actually-financial completion records, it's internal-only, it has one real trust boundary at the course-platform-to-Crunch-Ledger call).
- The concrete artifact that activity produces (a document, a test, a gate, a runbook).
- Who owns it.

This should read like the `phases` table from Lecture 1 and Exercise 1, populated for a service that doesn't exist yet — the same exercise a real design review does before writing the first line of infrastructure code.

## Task 2 — Threat-model the one trust boundary that matters

Crunch Ledger has exactly one meaningful trust boundary: the call from the course platform's backend into Crunch Ledger. In `threat-model.md`, run a lightweight STRIDE pass (Week 2) against that single boundary — you do not need a full data-flow diagram for the whole system, just this one edge, done properly. Name at least one threat per STRIDE category that's actually plausible for this specific boundary (not a template list copy-pasted from Week 2's own example), and a mitigation for each.

## Task 3 — Write the secure pipeline, unassisted

In `secure-pipeline.yml`, write a GitHub Actions workflow for Crunch Ledger's build/test/deploy pipeline that gets every hardening decision right **the first time**, rather than seeding flaws to fix later:

- Pinned actions (commit SHA, not tag) from the first line.
- An explicit, minimal `permissions:` block.
- A SAST gate and an SCA/secret-scan gate, both build-failing, both present before any deploy step.
- No hardcoded secrets anywhere — every credential referenced via `secrets.*`.
- No `curl | bash` or equivalent unpinned/unverified network-fetched execution anywhere.
- An artifact build, sign, and verify-before-deploy sequence, matching Exercise 3's shape.
- A `timeout-minutes` on the job.

You do not need `act` to actually run this workflow (there's no real Crunch Ledger app behind it) — but if you want extra confidence in your YAML syntax, sketching a minimal stub app and running it through `act` is a legitimate way to self-check.

## Task 4 — Justify your design in writing

In `design-rationale.md` (~300–400 words), explain: which of this week's six `PIPE-` flaw categories did you have to think hardest about avoiding, and why? Is there any hardening technique from Lectures 1–3 you deliberately chose **not** to apply to Crunch Ledger, and why (a design choice can legitimately be "this control's cost isn't justified for an internal-only service with no direct public exposure" — but it has to be an argued choice, not an omission you didn't notice).

## Expected result

- `sdlc-map.md` covers all six phases with Crunch-Ledger-specific activities, not generic restatements of Lecture 1.
- `threat-model.md` names at least one plausible, specific threat per STRIDE letter for the one real trust boundary.
- `secure-pipeline.yml` is syntactically valid YAML that gets every one of the six hardening categories right from the start.
- `design-rationale.md` shows real judgment, including at least one deliberate, argued trade-off.

## Submission

Commit all four files to `c50-week-10/challenge-01/` in your portfolio.
