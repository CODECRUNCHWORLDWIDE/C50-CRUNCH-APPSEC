# Challenge 1 — Write a Rules-of-Engagement Document

**Time:** ~45 minutes. **Difficulty:** Medium. **No single right answer, but a clear right shape.**

## The scenario

You've built an isolated lab (Exercise 1), mapped an attack surface (Exercise 2), and started scoring risk (Exercise 3). Everything you've done so far has been informal — you, in your own lab, doing your own thing. Professional security work is never that informal, even when you're the only person involved: it's governed by a **Rules of Engagement (RoE)** document that states, in writing, exactly what's authorized, by whom, against what, and for how long.

This challenge has you write that document for yourself, as if you were both the client authorizing the work and the tester agreeing to its terms — because that's literally your situation this week. The exercise isn't busywork: it's the habit that keeps every remaining week of this course (and every real, paid engagement you do afterward) legal and bounded.

## Your task

Write `rules-of-engagement.md` covering every section below. Be specific — a RoE with vague language ("test the app for issues") is not a RoE, it's a wish.

### Required sections

1. **Parties.** Who is authorizing this work, and who is performing it? (In your case: you, in both roles — state that explicitly rather than skip the section.)
2. **Scope — in scope.** The exact targets, by name and address, that are authorized for testing. Reference your actual lab: `juice-shop` at `127.0.0.1:3000`, `dvwa` at `127.0.0.1:3001`, `webgoat` at `127.0.0.1:3002`, all on the `appsec-lab` Docker network.
3. **Scope — explicitly out of scope.** State plainly: anything **not** on the `appsec-lab` network, anything reachable via your normal home/office network or the internet, and any real, third-party system of any kind, is out of scope, full stop.
4. **Authorized techniques.** What kinds of testing are permitted this week — reconnaissance/attack-surface mapping, manual exploration, risk scoring. (You'll expand this list in later weeks' RoEs as the course adds techniques — note that this week's list is intentionally narrow.)
5. **Explicitly prohibited actions.** Anything that could damage the lab beyond an easy reset, anything that would (even accidentally) generate traffic toward a real external system, and anything targeting a system outside the defined scope.
6. **Testing window.** Start and end dates/times for this authorization (tie it to this week of the course).
7. **Data handling.** Since your lab targets contain only synthetic/seed data, state that explicitly — and state what you'd do differently if a target ever contained real personal data (it should never, in this course, but a real RoE always addresses this).
8. **Rollback/reset plan.** Reference your `lab-teardown.sh`/`lab-setup.sh` from Exercise 1 as the documented recovery process if a target breaks.
9. **Signatures.** Two lines — "Authorized by" and "Performed by" — both your name, both dated. Yes, even alone. This is the habit, not theater.

## Constraints

- Every scope statement must be **specific enough that a stranger reading only this document could tell you exactly what's in bounds** — no "the lab environment," name the actual hosts and ports.
- The out-of-scope section must be at least as detailed as the in-scope section. A RoE that only says what's allowed, without saying what's forbidden, isn't doing its job.
- Reference real files from your own Exercise 1–3 work (`lab-setup.sh`, your `appsec.db`) rather than writing generic placeholders.

## Hints

<details>
<summary>On why "self-authorization" still matters</summary>

It might feel silly to write a formal authorization to yourself. The value isn't ceremony — it's that writing the document forces you to *actually think through* scope boundaries precisely, the same thinking you'll need when the "client" is someone else and getting scope wrong has real consequences. Treat this as a rehearsal with the exact same rigor as the real thing.

</details>

<details>
<summary>On the testing-window section</summary>

A real RoE always has a defined start and end — engagements aren't open-ended. Even for your own lab, picking a window (say, this week's dates) and sticking to it is the habit; in later weeks you'll write a fresh RoE per new technique category as the course's authorized scope grows.

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|----------------|
| Scope precision | "Test the lab" | Named hosts, ports, and network, matching your actual Exercise 1 setup |
| Out-of-scope clarity | Missing or an afterthought | As detailed as in-scope, explicitly rules out real/external systems |
| Technique boundaries | Vague ("do security testing") | Names the specific activities this week's course content actually covers |
| Rollback plan | Not mentioned | References your actual `lab-setup.sh`/`lab-teardown.sh` |
| Self-awareness | Treats self-authorization as pointless | States clearly why the discipline matters even when the tester and authorizer are the same person |

## Submission

Commit `rules-of-engagement.md` to your portfolio under `c50-week-01/challenge-01/`. You'll reference and extend this document's structure — never its literal content, since scope grows — for every remaining week of this course that adds a new class of technique.
