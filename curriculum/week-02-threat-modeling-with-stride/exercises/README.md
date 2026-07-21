# Week 2 — Exercises

Three guided exercises, ~90 min each, done in order — each one's output feeds the next. All three run against the same Juice Shop slice from the week README: **login, browse, basket/checkout, admin panel**.

1. **[Exercise 1 — Draw a DFD](exercise-01-draw-a-dfd.md)** — build the data-flow diagram yourself in Mermaid, with trust boundaries marked.
2. **[Exercise 2 — STRIDE-per-element pass](exercise-02-stride-per-element.md)** — run STRIDE against every element on your diagram; produce a threat list.
3. **[Exercise 3 — Threat model as data](exercise-03-threat-model-as-data.md)** — load your threats into SQLite with Python, then query your own risk register.

## Before you start

- Your Week 1 lab is running: `docker ps` shows `juice-shop` reachable at `http://localhost:3000`.
- You've read all three lectures.
- Python 3.10+ and `sqlite3` work from your terminal (`python3 --version`, `python3 -c "import sqlite3; print(sqlite3.sqlite_version)"`).

## Suggested workflow

- Open Juice Shop in a browser tab (`localhost:3000`) beside your editor — click through the four flows (register/log in, search a product, add to basket, try to reach `/#/administration`) once before you diagram anything. You're observing your own owned lab instance, not testing it.
- Do the exercises **in order** — Exercise 2 needs Exercise 1's diagram; Exercise 3 needs Exercise 2's threat list.
- Keep every deliverable in one folder, `week-02-exercises/`, in your portfolio — you'll extend this exact folder in the mini-project.

## A note on scope

These exercises reason about Juice Shop's *design*, using knowledge that's publicly documented by the OWASP Juice Shop project itself (it's an intentionally-vulnerable teaching app, built precisely so its flaw categories can be named and studied). Nothing here asks you to run an exploit, a scanner, or any tool beyond a browser and your own reasoning. If you find yourself about to type an actual attack payload into a form "just to check" — stop; that belongs in a future week, with a defined scope, once you've explicitly moved from *modeling* to *testing*.
