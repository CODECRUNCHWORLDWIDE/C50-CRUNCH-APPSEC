# Week 2 — Challenges

Two open-ended problems. Unlike the exercises — which walk you through Juice Shop step by step — these hand you far less structure. The skill here is judgment: choosing your own scope, defending your own scoring, and knowing when your model is good enough to ship. Do them after the three exercises.

1. **[Challenge 1 — Model a real lab app](challenge-01-model-a-real-lab-app.md)** — run the full method (DFD → STRIDE → ranked, stored threat model) against **DVWA or WebGoat**, a different app from your Week 1 lab, with none of Exercise 1–3's guided prompts. *(~90 min.)*
2. **[Challenge 2 — Attack tree for one attacker goal](challenge-02-attack-tree-for-one-goal.md)** — pick one concrete attacker goal from your threat model and build an attack tree showing the paths that reach it, tying every leaf to a STRIDE category and a detection point. *(~90 min.)*

## How these are judged

There's no row-count answer key. Instead, each challenge tells you what a *strong* submission looks like. You're being graded on:

- **Method discipline** — did you actually follow DFD → STRIDE-per-element → score → disposition, in that order, or did you jump straight to a threat list from intuition?
- **Defensible scoring** — can you justify every likelihood/impact number against Lecture 3's rubric, not just assert it?
- **Judgment on scope and depth** — did you time-box sensibly (Lecture 3, Section 5) instead of either stopping too shallow or spiraling into an exhaustive Level 3 diagram?
- **The attacker/defender pairing** — does every offensive step in Challenge 2's attack tree carry a matching detection point, the way Week 1 and every lecture this week have modeled?

Keep your work in `challenge-01/` and `challenge-02/` folders with your diagrams, your database (Challenge 1), and your written reasoning. The reasoning is the point — a correct-looking diagram with no stated rationale is an incomplete answer.
