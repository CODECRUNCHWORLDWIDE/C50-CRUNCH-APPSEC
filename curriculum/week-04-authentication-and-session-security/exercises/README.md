# Week 4 — Exercises

Three guided exercises, ~90 min each, all against `crunch-authlab` — the login app you build yourself in Exercise 1 and keep hardening through Exercise 3. **Type the code yourself, run it, and read the output before moving on** — the whole point this week is watching a real attack succeed against your own broken code, then watching it fail against your own fixed code.

1. **[Exercise 1 — Break and fix password storage](exercise-01-break-and-fix-password-storage.md)** — build `crunch-authlab` v0 with plaintext passwords, "crack" it two ways, then rebuild storage on argon2id.
2. **[Exercise 2 — Add TOTP MFA](exercise-02-add-totp-mfa.md)** — add enrollment, verification, and hashed recovery codes to the login state machine.
3. **[Exercise 3 — Harden session cookies](exercise-03-harden-session-cookies.md)** — fix session ID entropy, cookie flags, fixation, timeout, and logout.

## Before you start

- You've read all three lectures for this week.
- Python 3.10+ and `pip` work from your terminal.
- Your Week 1 `appsec-lab` Docker network is up (Exercise 1 uses DVWA's Brute Force module for one comparison; `crunch-authlab` itself runs directly on your host via `python3`, not in Docker — it's your own code, isolation of the *lab network* is about the pre-built vulnerable targets, not the app you're writing).

## Set up the project once

```bash
mkdir -p ~/appsec-lab/crunch-authlab && cd ~/appsec-lab/crunch-authlab
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install flask argon2-cffi pyotp
```

Keep this virtual environment active for all three exercises — each one edits the same `app.py` and `authlab.db` in place, building on the exercise before it. Re-activate with `source venv/bin/activate` any time you open a new terminal.

## Suggested workflow

- Work through the tasks in order — Exercise 2 and 3 assume Exercise 1's argon2id storage is already in place.
- After every fix, **re-run the attack from before the fix** and confirm it now fails. A fix you haven't proven against the original attack isn't done.
- Keep every version of `app.py` you're asked to save (`app_v0.py`, `app_v1.py`, …) — the mini-project's write-up compares them.
- Save your own notes on what surprised you as you go; the mini-project's reflection draws on them.
