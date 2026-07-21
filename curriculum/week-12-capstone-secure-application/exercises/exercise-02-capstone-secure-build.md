# Exercise 2 — Capstone Secure Build

**Goal:** Implement every fix from Lecture 2 against your own Crunch Ledger checkout, in the priority order Exercise 1's risk register computed — not the README's numbered list — and re-test each one by hand before moving to the next.

**Estimated time:** 120 minutes.

## Setup

```bash
cd c50-week-12/crunch-ledger    # continue from Exercise 1
sqlite3 risk_register.db "SELECT priority, risk_id, element, description FROM risk_register ORDER BY priority, risk_id;"
```

Work down this list. If your register's `P0` row is the missing role check on `/admin/approve`, fix that first — even though it's numbered "VULN #5" in the README and comes after "VULN #1–4" there. The register's priority order, not the README's numbering, is the order that reflects actual risk, and following it is itself part of what this exercise is grading.

## Task 1 — Auth and session (P0/P1 rows touching login or session)

Apply Lecture 2 Section 1's fixes: swap `hash_password`/`login` to `werkzeug.security`'s `generate_password_hash`/`check_password_hash`, re-run `seed.py` against a fresh `crunchledger.db`, and add the three `SESSION_COOKIE_*` config lines.

Re-test:

```bash
python3 app.py
curl -s -c erin.txt -X POST http://127.0.0.1:5100/login -d "username=cl-erin&password=labpass1" -D headers.txt
grep -i "set-cookie" headers.txt   # confirm HttpOnly; SameSite=Lax present
```

## Task 2 — Injection defense

Apply Lecture 2 Section 2's parameterized-query fix to `search_expenses`. Re-test with the exact injection probe:

```bash
curl -s "http://127.0.0.1:5100/expenses/search?q=%25%27%20OR%201%3D1%20--" -b erin.txt
```

Expect an empty or near-empty result, not the full expense table.

## Task 3 — Access control

Apply Lecture 2 Section 3's ownership filter to `get_expense` and the `require_role` decorator to `approve_expense` and `admin/users`. Re-test all three:

```bash
curl -s -i -b erin.txt http://127.0.0.1:5100/expenses/3          # cl-erin doesn't own expense 3 -- expect 404
curl -s -i -b erin.txt -X POST http://127.0.0.1:5100/admin/approve/1   # employee approving -- expect 403
curl -s -c mona.txt -X POST http://127.0.0.1:5100/login -d "username=cl-mona&password=labpass1"
curl -s -i -b mona.txt -X POST http://127.0.0.1:5100/admin/approve/1  # manager approving -- expect 200
```

## Task 4 — Secrets and applied crypto

Remove both hardcoded values from `config.py`, export both as environment variables, and apply Lecture 2 Section 4's fixes to `make_reset_token` (`secrets.token_urlsafe`) and `webhook_reimburse` (`hmac.compare_digest`). Re-test:

```bash
unset FLASK_SECRET_KEY WEBHOOK_SIGNING_SECRET
python3 app.py    # expect: crash with a clear KeyError, NOT a silent default

export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export WEBHOOK_SIGNING_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
python3 app.py    # now starts cleanly
```

```bash
curl -s -X POST http://127.0.0.1:5100/password-reset/request -d "username=cl-erin"
# confirm the returned token is a long, non-numeric-only urlsafe string, not 8 digits
```

## Task 5 — API and supply-chain security

Add `@require_role("manager", "admin")` to `/api/expenses`. Run `pip-audit -r requirements.txt`, read the advisory, and bump the pin deliberately (`flask==3.0.3`, `cryptography>=42.0.0` or whatever the tool currently recommends). Reinstall and re-run the full smoke test before continuing:

```bash
pip install -r requirements.txt
pip-audit -r requirements.txt   # expect: no advisories found
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5100/api/expenses   # expect: 401/403, not 200
```

## Task 6 — Secure SDLC / CI/CD

Rewrite `ci_pipeline.yml` per Lecture 2 Section 6 — remove `|| true` from the test step, add blocking `bandit` and `pip-audit` steps, and add a `deploy` job gated on `needs: security-gates` with an `environment: production` block. There's no CI runner to actually execute this in the lab, so "re-testing" this fix means reading the YAML back and confirming, line by line, that a failing test or a medium+ Bandit finding would in fact stop the `deploy` job from running — write this confirmation down as a sentence in your remediation notes, since there's no `curl` command that proves a YAML gate.

## Task 7 — Full re-test pass

Run every command from Lecture 2 Section 7 in one sitting, back to back, and confirm every single one now behaves as a hardened route should. This is the checkpoint before Exercise 3's independent hunt — if anything here still fails, fix it now, not later.

## Done when…

- [ ] Every row in `risk_register` that maps to one of the eleven numbered vulnerabilities now has a corresponding code change, committed.
- [ ] The full re-test pass from Task 7 passes every command, with output you've actually read (not assumed).
- [ ] `python3 app.py` fails loudly with `KeyError` when `FLASK_SECRET_KEY`/`WEBHOOK_SIGNING_SECRET` are unset — proving the secrets fix removed the hardcoded fallback entirely, not just moved it.
- [ ] `pip-audit -r requirements.txt` reports zero advisories.
- [ ] You can explain, for each of the six tasks above, which risk-register row(s) it closes and why that fix is the right shape (query-level filter, decorator, environment injection, constant-time comparison) rather than just "a fix that happens to work."

## Stretch

- Add a `before_request` hook that logs every request's route, method, `user_id`, and outcome to a new `access_log` table — a lightweight audit trail that starts closing the Repudiation gap Exercise 1's STRIDE table should have surfaced.
- Fix the manager-approving-their-own-expense business-logic gap Lecture 3 Section 6 previews, ahead of schedule — it isn't one of the eleven numbered vulnerabilities, so finding and fixing it here is extra credit toward Challenge 1.

## Submission

Commit the fully updated `app.py`, `config.py`, `requirements.txt`, `ci_pipeline.yml`, and a `remediation-notes.md` summarizing what changed and why, to `c50-week-12/exercise-02/`. Exercise 3 runs the independent hunt against exactly this state.
