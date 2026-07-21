# Mini-Project — Eliminate Every Injection Flaw, Prove It With a Payload Library

> Take Crunch Notes from seven deliberate injection flaws to zero, converting every database access to parameterized SQL, adding context-appropriate input validation and output encoding everywhere it's needed — and prove each fix by re-running your full stored payload library against the finished app.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

This is the week's capstone: the complete loop from "here's a broken app" to "here's proof it's fixed," using nothing but the tools this week taught — parameterized queries, allowlist validation, context-aware output encoding, and a SQLite-backed payload library instead of a spreadsheet or a gut feeling.

---

## Deliverable

A directory in your portfolio `c50-week-05/mini-project/` containing:

1. `app.py` — the fully converted Crunch Notes source, all 7 VULNs closed.
2. `findings.db` — your SQLite findings database: `findings`, `payload_library`, `verifications`, and `query_log` tables, fully populated.
3. `run_full_verification.py` — a single script that runs your **entire** payload library against **every** route and writes fresh `verifications` rows.
4. `report.md` — a written summary tying it all together (structure below).

---

## Requirements

### Part 1 — Every flaw closed (verify, don't redo from scratch)

All 7 VULNs from the week README's table must be fixed in the final `app.py`:

- VULN #1, #2 (SQLi half), #5, #6 — parameterized queries, `?` placeholders, no string-built SQL anywhere `db.execute()` is called.
- VULN #4 — allowlist validation (`is_valid_target()`) **and** `subprocess.run([...])` with no shell.
- VULN #2 (XSS half), #3 — `|safe` removed; Jinja2 autoescaping active on every user-controlled template value.
- VULN #7 — `textContent` instead of `innerHTML` in the client-side script.

### Part 2 — Payload library (extend everything from the week)

- **At least 15 payloads** across all three categories (`sqli`, `cmdi`, `xss`), combining everything from Exercises 1–3 and Challenges 1–2 plus **at least 3 new payloads you write yourself** that don't duplicate any earlier one.
- At least 2 payloads per category must target a **different route** than the one they were originally recorded against (a SQLi payload written for `/login` also tried against `/search`, etc.) — proving the fix generalizes, not just "this one exact input on this one exact route."

### Part 3 — Full verification sweep

- `run_full_verification.py` runs **every** payload in `payload_library` against **every** route that accepts user input (`/login`, `/search`, `/notes/new` then `/notes`, `/diagnostics/ping`, `/profile`, `/status`), recording a `verifications` row for each (route × payload) combination it makes sense to try.
- **Zero rows** in `SELECT * FROM verifications WHERE result = 'allowed'` at the end.

### Part 4 — `report.md`

Write a short report covering:

1. **Executive summary** (~150 words) — as if handing this to a non-technical stakeholder: what kind of bug was this app full of, what did fixing it actually involve, and why should they trust it's actually fixed now (not just "we tried").
2. **Before/after table** — one row per VULN (1–7): route, category, the one-sentence fix, and the payload-count that now verifies as blocked.
3. **One query that surprised you** — run something exploratory against `findings.db` (e.g., "which category took the most payloads to fully close?", "did any single payload catch more than one VULN?") and report what you found.
4. **Reflection** (~150 words): which fix category — parameterization, allowlist validation, or output encoding — took the most discipline to get right, and why? Where did you almost reach for a blocklist or an escape-by-hand shortcut before catching yourself?

---

## Milestones

- **Milestone 1 (45 min):** Confirm all fixes from Exercises 1–3 and Challenges 1–2 are present in one clean `app.py`; run it and smoke-test every route by hand.
- **Milestone 2 (45 min):** Consolidate and extend `payload_library` to 15+ payloads across all three categories, with the cross-route requirement met.
- **Milestone 3 (60 min):** Write and run `run_full_verification.py`; chase down and fix any `allowed` result until the sweep is clean.
- **Milestone 4 (30 min):** Write `report.md`, run the report queries, proofread the executive summary as if a non-technical reader sees it first.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Completeness of fixes | 30% | All 7 VULNs closed, using the structurally correct technique for each (not a workaround that happens to pass one test) |
| Payload library rigor | 25% | 15+ payloads, real diversity across categories, cross-route testing shows the fix generalizes |
| Verification sweep | 25% | `run_full_verification.py` is real and runnable; zero `allowed` results at the end; you show your work, not just a claim |
| Report clarity | 20% | Executive summary readable by a non-technical stakeholder; before/after table is accurate and specific |

---

## Why this matters

This loop — break it, understand why, fix it structurally, prove the fix against stored evidence — is the shape of real vulnerability remediation work, not a classroom exercise you'll leave behind. The `findings.db` schema you built this week (findings → payload library → verifications) is one you'll extend, not replace, straight through Week 11's secure code review and the Week 12 capstone.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 6 — Access control & authorization](../../week-06-access-control-and-authorization/).
