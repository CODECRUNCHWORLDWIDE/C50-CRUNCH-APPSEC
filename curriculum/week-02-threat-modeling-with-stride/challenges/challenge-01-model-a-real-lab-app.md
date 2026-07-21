# Challenge 1 — Model a Real Lab App

**Time:** ~90 minutes. **Difficulty:** Medium-high. **Far less guidance than the exercises — that's deliberate.**

## The scenario

Every exercise this week held your hand through Juice Shop. Real threat modeling doesn't come with numbered tasks — someone hands you an application (or you're building one) and says "threat-model this," full stop. This challenge is that moment. You'll run the entire method — DFD, STRIDE-per-element, scoring, disposition, storage as data — against **a different app from your Week 1 lab**, with none of Exercise 1–3's step-by-step prompts.

## Your task

1. **Choose your target:** either **DVWA** (`localhost:3001`) or **WebGoat** (`localhost:3002`) — pick whichever is running cleanly in your lab. State which one you chose and why in one sentence.

2. **Choose your scope.** You are *not* modeling the entire application — that's an unbounded task. Pick 3–4 flows worth modeling (e.g., for DVWA: the security-level setting, a vulnerable form of your choosing, the login, and one admin-only action). Write down your scope in one short paragraph before you diagram anything — this is the single most important judgment call in the whole challenge, and it's graded as such.

3. **Draw the DFD.** Level 1, Mermaid, all four element types, trust boundaries marked — exactly the standard from Lecture 1, applied without a worked example to copy from.

4. **Run STRIDE-per-element.** Minimum 20 threats this time (more than Exercise 2 — you have two full lectures of practice behind you now), across at least 4 STRIDE categories.

5. **Score and store.** Build the same two-table SQLite schema from Lecture 3 / Exercise 3, load every threat via Python, and produce the same five categories of query (top risks, count by category, accepted risks, per-element threats, average risk per element).

6. **Write a one-page risk-ranked mitigation summary** (`summary.md`, 300–500 words) as if handing it to that app's (fictional) development team: your top 5 risks, in order, each with its disposition and control, written in plain language a developer with no security background could act on immediately.

## Constraints

- **Time-box yourself explicitly.** Write down your start time and stop at 90 minutes even if you feel unfinished — this is Lecture 3 Section 5's rule, and this challenge is where you practice it under real pressure instead of reading about it.
- No exploitation. You are reasoning about design and (for DVWA/WebGoat specifically) about publicly documented vulnerability categories these apps are built to teach — not running an actual attack payload. If a task tempts you to type a real exploit string into a form "to see what happens," don't; note it as a threat instead and move on.
- Your scope (Task 2) must be written down *before* the diagram, not reverse-engineered afterward to match what you happened to model.

## Hints

<details>
<summary>On choosing scope (Task 2)</summary>

A good scope for 90 minutes is roughly the same size as this week's Juice Shop slice: one authentication flow, one flow that clearly crosses a privilege boundary, and one or two flows that exercise a specific vulnerability class the app is known for (DVWA is organized by vulnerability category — pick 2–3 categories, not all of them; WebGoat is organized by lesson — pick 2–3 lessons). Resist the urge to model "the whole app" — that's a multi-day project, not a 90-minute challenge, and a good threat modeler knows how to scope down as much as how to enumerate threats.

</details>

<details>
<summary>On what "far less guidance" is testing</summary>

The exercises taught you the mechanics with training wheels on. This challenge checks whether the mechanics survived the training wheels coming off — can you decide, unprompted, which element types exist on your own diagram, which STRIDE letters apply to each, and how deep is "deep enough"? If you find yourself wanting to re-read Lecture 1–3 mid-challenge, that's fine and expected the first time; the goal is needing to less and less each week going forward.

</details>

## How success is judged

| Signal | Weak submission | Strong submission |
|---|---|---|
| Scope | Undefined, drifts mid-task, or attempts the whole app | Stated up front, appropriately sized for 90 minutes, held to |
| DFD correctness | Missing element types, no trust boundaries, or a network diagram in disguise | All four element types present, boundaries marked, every flow labeled with real data |
| STRIDE coverage | Threats cluster on one favorite category | At least 4 STRIDE categories represented, matched correctly to element type |
| Scoring discipline | Numbers feel arbitrary or all cluster at 3 | Each score traceable to Lecture 3's rubric language |
| Storage | Threats live only in prose | Real SQLite database, all five query types run cleanly |
| Communication | `summary.md` reads like a threat list | `summary.md` reads like something a developer could act on today |

## Submission

Commit your diagram, database, queries, and `summary.md` to `week-02-challenges/challenge-01/` in your portfolio.
