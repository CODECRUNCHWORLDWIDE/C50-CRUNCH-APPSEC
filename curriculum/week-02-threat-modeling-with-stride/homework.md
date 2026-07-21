# Week 2 — Homework

Five problems, ~5 hours total, spread across the week. These reinforce the lectures with a mix of diagramming, a written explanation, a database exercise, and a judgment task. Commit each.

All problems can use your Week 1 lab (Juice Shop, DVWA, WebGoat) unless a problem says otherwise. As always: identification and reasoning only, no exploitation, everything against your own isolated targets.

---

## Problem 1 — DFD for something you already know (60 min)

Draw a Level 1 DFD, with trust boundaries marked, for an application you're already familiar with — a personal project, something from a prior CodeCrunch course (e.g., your [C16 Crunch Pro Web Backend](../../../C16-CRUNCH-PRO-WEB-BACKEND/) project if you've taken it), or even a simple app you use daily and can reason about from its visible behavior (e.g., "how does a typical email client's 'reset password' flow probably work").

1. Draw the diagram (Mermaid), all four element types, at least two trust boundaries.
2. Write 3–4 sentences: which trust boundary in your diagram feels like it carries the most risk, and why?

**Deliver** `homework-01-dfd.md`.

---

## Problem 2 — STRIDE-per-element on a login you didn't build (60 min)

Pick **WebGoat's** login flow (or DVWA's, if WebGoat isn't in your lab) — one you haven't modeled yet this week. Run a focused STRIDE-per-element pass on just the login process and the user data store it touches (not the whole app).

1. Produce at least 10 threats across at least 4 STRIDE categories, following the exact sentence shape from Exercise 2, Task 3.
2. For each, note the mitigation direction.

**Deliver** `homework-02-login-stride.md`.

---

## Problem 3 — Query practice against your own threat database (60 min)

Using the `threatmodel.db` you built in Exercise 3 (or the mini-project, if you've reached it), write and run five **new** SQL queries not already in your `queries.sql`:

1. Every threat where `impact = 5` regardless of likelihood (the "if this happens, it's catastrophic" list — different from "top risk score," which could hide a low-likelihood-but-catastrophic threat behind higher-scored-but-less-severe ones).
2. The single element with the most *open* threats attached (a `GROUP BY` + `ORDER BY` + `LIMIT 1`).
3. A count of threats per `disposition` value — how many are mitigate vs. eliminate vs. transfer vs. accept overall?
4. Every threat whose description mentions a specific keyword of your choosing (e.g., `'password'`, `'token'`, `'admin'`) using `LIKE`.
5. One query of your own design, plus a one-sentence explanation of the question it answers.

**Deliver** `homework-03-queries.sql` and `homework-03-results.md` with the outputs.

---

## Problem 4 — Explain threat modeling vs. penetration testing (45 min)

In `homework-04-writeup.md`, in prose (no more than 400 words total), using a scenario **not** from this week's lectures:

1. Invent a short, plausible scenario (2–3 sentences) — a feature being designed or a system being tested.
2. Explain which activity — threat modeling or penetration testing — you'd reach for first, and why, referencing Lecture 3 Section 6's comparison table.
3. Explain what the *other* activity would add once the first one's done, and why neither alone is sufficient.
4. Name one real cost of skipping threat modeling and going straight to penetration testing on a brand-new design.

---

## Problem 5 — A disposition you disagree with (45 min)

Pick any three threats from your Exercise 2, Exercise 3, or a challenge's threat list where you assigned a **mitigate** disposition. For each:

1. Argue, in 2–3 sentences, why **eliminate** or **transfer** might actually be the better disposition instead — even if you still think mitigate was right, make the strongest honest case for the alternative.
2. State which disposition you'd actually keep, and why, after making that case.

This is a deliberate exercise in not defaulting to "mitigate" for everything just because it's the easiest box to check — a common real-world failure mode where teams patch symptom after symptom instead of asking whether the feature or design itself should change.

**Deliver** `homework-05-dispositions.md`.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 60 min |
| 2 | 60 min |
| 3 | 60 min |
| 4 | 45 min |
| 5 | 45 min |
| **Total** | **~4.5 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
