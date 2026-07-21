# Week 2 — Threat Modeling with STRIDE

> **Goal:** by Sunday you can take a system you've never seen before, draw its data-flow diagram, run STRIDE against every element on it, and hand a development team a risk-ranked, queryable list of threats and mitigations — before a single exploit is ever attempted.

Welcome back to **C50 · Crunch AppSec**. Week 1 gave you the vocabulary (assets, threats, risk, the CIA triad) and a legal, isolated lab to practice in. This week gives you the *method*: **threat modeling**, the structured practice of finding security problems by reasoning about a design, on paper, before code is exploited or sometimes before it's even written. It is the single highest-leverage habit in this entire course — an hour spent threat-modeling a login flow routinely finds more real vulnerabilities than a day spent randomly clicking around it.

You'll learn **data-flow diagrams (DFDs)** — the map that shows how data actually moves through a system and where it crosses a **trust boundary** — and **STRIDE**, Microsoft's six-category taxonomy (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) for enumerating what can go wrong at each point on that map. Applied element by element, STRIDE turns "I have a bad feeling about this design" into a specific, repeatable, arguable list — and this week you'll store that list as **queryable data in SQLite**, not a spreadsheet, so a risk register is something you can actually query, not just skim.

> **Ethics & legality — binding, every week.** Everything below is **authorized, legal, defensive-minded** security work performed **only inside the isolated lab** you built in Week 1 — deliberately-vulnerable targets (Juice Shop, DVWA, WebGoat) on a Docker network with no route to the internet or to any real system. Threat modeling is a *design-review* activity: you are reasoning about a system you own, not touching a system that belongs to someone else. Where this week names a real vulnerability class in your lab app (e.g., "the login endpoint is susceptible to SQL injection"), that is threat *identification*, not an exploitation walkthrough — exploiting and fixing those specific classes is Weeks 3, 5, and 6. Every threat you name here gets a defensive mitigation in the same breath. Written authorization, defined scope, and the law govern every exercise this week and every week after it.

## Learning objectives

By the end of this week, you will be able to:

- **Draw** a data-flow diagram with the four correct element types — external entities, processes, data stores, data flows — and mark every place a flow crosses a **trust boundary**.
- **Apply STRIDE per element** — Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — as a repeatable enumeration method, knowing which STRIDE categories apply to which element type and why.
- **Score** each threat as **risk = likelihood × impact**, choose a disposition (**mitigate, eliminate, transfer, accept**), and connect it to one concrete defensive control.
- **Distinguish threat modeling from penetration testing** — design-time reasoning about what *could* go wrong versus runtime verification of what *does* — and know which one to reach for and when.
- **Store a threat model as queryable data** — an `elements` table and a `threats` table in SQLite, populated with SQL or Python — so "what's our top 5 risk?" is one query, not a spreadsheet scroll.
- **Know when to stop** — threat modeling has diminishing returns past a certain depth; you'll practice time-boxing a pass instead of chasing an exhaustive, paralyzing one.

## Prerequisites

- **Week 1 completed**, specifically: your isolated `appsec-lab` Docker network is up, with **Juice Shop** reachable at `localhost:3000` and (ideally) DVWA at `localhost:3001` and WebGoat at `localhost:3002`. If any container isn't running, `docker compose up -d` from your Week 1 lab directory before you start.
- Python 3.10+ and `sqlite3` (ships with Python) — same as Week 1, no new install.
- Comfortable clicking through a web app in a browser and reading its network requests (your browser's dev tools, `F12` → Network tab). You are **not** running any scanning or exploitation tool this week — a browser is the only tool this week's exercises require.
- Nothing else. This week defines DFDs and STRIDE from scratch.

## This week's target system

Every lecture and exercise threat-models the same slice of **OWASP Juice Shop** — the app you stood up in Week 1's Exercise 1 — so you can compare your diagram and your threat list to the worked examples directly. We model four things a shopper and an admin do:

1. **Log in** (`POST /rest/user/login`) — credentials go from browser to API to the user store and a session token comes back.
2. **Browse products** (`GET /rest/products/search`) — a public, unauthenticated read.
3. **Add to basket and check out** (`POST /api/BasketItems`, `POST /rest/basket/:id/checkout`) — an authenticated write.
4. **Reach the admin panel** (`/#/administration`) — a privileged view that should be reachable only by an admin.

That's a small enough slice to diagram completely in an hour, and it's rich enough — one public read, one authenticated write, one login boundary, one privilege boundary — to make every STRIDE category show up naturally. Challenge 1 asks you to repeat the whole method on a **different** lab app (DVWA or WebGoat) with far less hand-holding.

## This week's map

Work top to bottom. Each piece assumes the ones before it.

| # | File | What's inside | ~Time |
|--:|------|---------------|------:|
| 1 | [lecture-notes/01-data-flow-diagrams-and-trust-boundaries.md](./lecture-notes/01-data-flow-diagrams-and-trust-boundaries.md) | The four DFD element types, trust boundaries, levels of abstraction, a worked Juice Shop diagram | 2h |
| 2 | [lecture-notes/02-the-stride-taxonomy.md](./lecture-notes/02-the-stride-taxonomy.md) | Each STRIDE category defined, which categories apply to which element type, STRIDE-per-element walked across the Juice Shop diagram | 2h |
| 3 | [lecture-notes/03-ranking-and-mitigating-threats.md](./lecture-notes/03-ranking-and-mitigating-threats.md) | Risk = likelihood × impact, the four dispositions, storing the model in SQLite, threat modeling vs. pen-testing, when to stop | 2h |
| 4 | [exercises/exercise-01-draw-a-dfd.md](./exercises/exercise-01-draw-a-dfd.md) | Draw the Juice Shop DFD yourself in Mermaid, mark every trust boundary | 1.5h |
| 5 | [exercises/exercise-02-stride-per-element.md](./exercises/exercise-02-stride-per-element.md) | Run STRIDE against every element on your diagram; produce a threat list | 1.5h |
| 6 | [exercises/exercise-03-threat-model-as-data.md](./exercises/exercise-03-threat-model-as-data.md) | Build the SQLite schema, load your threats with Python, query your own risk register | 1.5h |
| 7 | [challenges/challenge-01-model-a-real-lab-app.md](./challenges/challenge-01-model-a-real-lab-app.md) | Threat-model DVWA or WebGoat end to end, with far less guidance | 1.5h |
| 8 | [challenges/challenge-02-attack-tree-for-one-goal.md](./challenges/challenge-02-attack-tree-for-one-goal.md) | Build an attack tree for one attacker goal; tie every leaf to a STRIDE category and a detection point | 1.5h |
| 9 | [mini-project/README.md](./mini-project/README.md) | A complete STRIDE threat model of a lab app: DFD, threats-as-data, and a risk-ranked mitigation report | 3h |
| 10 | [homework.md](./homework.md) | Extra practice, spread across the week | 5h |
| 11 | [quiz.md](./quiz.md) | 15 self-check questions + answer key | 1h |
| 12 | [resources.md](./resources.md) | Official docs, free tools, and the few links worth your time | — |

## Weekly schedule

Adds up to **~25 hours** this week. Treat it as a target, not a stopwatch — a good STRIDE pass rewards going slower, not faster.

| Day | Focus | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Daily Total |
|-----------|------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|------------:|
| Monday | DFDs & trust boundaries; draw your own | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Tuesday | STRIDE taxonomy; STRIDE-per-element | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Wednesday | Ranking, mitigating, storing as data | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Thursday | Model a second lab app | 0h | 0h | 1.5h | 0.5h | 1h | 0.5h | 3.5h |
| Friday | Attack tree for one attacker goal | 0h | 0h | 1.5h | 0.5h | 1h | 0.5h | 3.5h |
| Saturday | Mini-project | 0h | 0h | 0h | 0h | 0h | 2h | 2h |
| Sunday | Quiz + review | 0h | 0h | 0h | 1h | 0h | 0h | 1h |
| **Total** | | **6h** | **4.5h** | **3h** | **3.5h** | **5h** | **3h** | **25h** |

## By the end of this week you can…

- Look at any application — a lab target or a real one you're building — and draw the boxes, arrows, and trust-boundary lines that describe how data actually moves through it.
- Run a STRIDE-per-element pass without a template in front of you, because the method is now muscle memory: for each element, ask only the STRIDE categories that apply to *that* element type.
- Turn "this feels risky" into `risk_score = likelihood × impact`, defend the numbers you chose, and pick mitigate/eliminate/transfer/accept deliberately instead of by gut feel.
- Query your own threat model — "show me every open, high-risk Tampering threat" — in SQL, because you stored it as data from the start.
- Explain to a teammate, precisely, why you'd threat-model a design on Monday and penetration-test the shipped code in Week 3 — they answer different questions and neither substitutes for the other.

## Up next

[Week 3 — The OWASP Top 10, in depth](../week-03-owasp-top-10-deep-dive/) — this week you learned to *find and name* threats systematically; next week you learn the ten vulnerability classes that STRIDE's "Tampering" and "Elevation of Privilege" threats turn out to be, over and over, in real applications — and how to demonstrate and fix each one in your lab.

---

*Part of the Code Crunch Worldwide open curriculum · GPL-3.0 · If you find errors, please open an issue or PR.*
