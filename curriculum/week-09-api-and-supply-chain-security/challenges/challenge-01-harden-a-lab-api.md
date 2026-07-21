# Challenge 1 — Harden a Lab API End to End

**Target:** Your own `crunch-tasks-api`, with Exercises 1–2's fixes already applied, running at `http://127.0.0.1:5000`.

**Estimated time:** ~2 hours.

Exercises 1 and 2 closed the two flaws with the most hand-holding: BOLA and mass assignment. `crunch-tasks-api` still has three open items from the week README's table: **BFLA** (`DELETE /api/v1/admin/tasks/<id>`), **excessive data exposure** (`GET /api/v1/users/me`), and **missing rate limiting** (`POST /api/v1/login`). This challenge closes all three, using Lecture 2's design disciplines rather than the narrowest possible patch.

## Goal

Every route in `crunch-tasks-api` correctly enforces authentication, function-level authorization, object-level authorization, output shaping, and (where relevant) rate limiting — and you can prove all five, end to end, against a freshly restarted app.

## Rules

- Fix at the **design** level Lecture 2 taught, not the narrowest one-line patch: the BFLA fix should be a reusable `require_role()` helper (not an inline `if`), the data-exposure fix should be a `serialize_user()`/`serialize_task()` function used by *every* route that returns that object type (not a one-off `jsonify(...)` in a single route), and the rate limiter should apply via `Flask-Limiter` (or an equivalent token-bucket you implement yourself) rather than a hand-rolled counter that only covers `/login`.
- Every fix gets demonstrated (attack succeeds, pre-fix), remediated, and re-tested in **both** directions (attack now fails; the legitimate case — Bob's admin actions, Alice's own data, a normal login — still works).
- Extend your Exercise 3 database with a new `api_findings` table (design it yourself, following the same shape as `dependency_findings`: category, endpoint, evidence, remediation, retest result, status) rather than tracking these findings anywhere else.
- Do a full clean-restart re-test at the end: `python3 seed.py && python3 app.py`, then re-run every attack from Lectures 1–2 against the fresh process, and confirm every single one now fails the way its fix predicts.

## What "great" looks like

| Criterion | Weight | Detail |
|-----------|------:|--------|
| Completeness | 30% | All three remaining flaws demonstrated, fixed, and re-tested |
| Design quality | 25% | Fixes are reusable (helper functions, serializers, a real limiter), not narrow one-off patches |
| Evidence quality | 25% | Every claim backed by a real request/response, including the clean-restart re-test transcript |
| Findings record | 20% | `api_findings` table has one complete, honest row per flaw, `status = 'remediated'` only where actually re-tested |

## Deliverable

Your fully hardened `app.py`, `api-findings-schema.sql`, your extended findings database, and a `hardening-report.md` summarizing all three fixes with their before/after evidence.

## Submission

Commit everything to your portfolio under `c50-week-09/challenge-01/`.
