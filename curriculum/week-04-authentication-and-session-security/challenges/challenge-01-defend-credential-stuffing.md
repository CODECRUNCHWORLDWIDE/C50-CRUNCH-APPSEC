# Challenge 1 — Defend Against Credential Stuffing

**Time:** ~90 minutes. **Difficulty:** Medium. **No single right answer on the defense's exact thresholds — but the defense must genuinely work.**

## The scenario

Lecture 1, Section 6 drew the line: credential stuffing never touches your password hashing — it replays username/password pairs leaked from **some other** breach against **your** login, betting some fraction of your users reused a password. Your job this challenge is to be both sides of that story on your own lab app: write the attack, watch it succeed, then close it and prove it's closed.

## Setup

Continue from `app_v3.py` (Exercise 3's fully session-hardened version). Add three more accounts to `crunch-authlab` with passwords you'll deliberately reuse in a fake "leaked" list, to simulate real stuffing:

```sql
INSERT INTO users (username, password_hash) VALUES
  ('katherine', '$argon2id$...'),   -- hash whatever password you choose with your hash_password() helper
  ('dennis',    '$argon2id$...'),
  ('barbara',   '$argon2id$...');
```

## Part 1 — Write the attack, and watch it work

Create `stuffing_attack.py` — a script that simulates an attacker replaying a "breach dump" of username/password pairs against your login, one request per pair, no delay:

```python
import requests

# A fictional "leaked from elsewhere" combo list — a mix of correct and wrong pairs,
# the way a real stuffing list is mostly wrong but occasionally right because of reuse.
combo_list = [
    ("grace", "CorrectHorseBattery1"),   # correct — she reused it (Exercise 1's original password)
    ("ada", "hunter2"),                   # wrong
    ("katherine", "<the password you gave her>"),  # correct
    ("dennis", "password1"),              # wrong
    ("barbara", "<the password you gave her>"),     # correct
    ("alan", "wrongguess"),               # wrong
    # ... pad to at least 30 pairs across your accounts, mostly wrong, a few right
]

BASE = "http://127.0.0.1:5000"
for username, password in combo_list:
    resp = requests.post(f"{BASE}/login", data={"username": username, "password": password})
    print(f"{username:12s} -> {resp.status_code}")
```

Run it against your **current, undefended** login (no rate limit yet). **Expected:** every correct pair succeeds, immediately, no friction — because nothing in `app_v3.py` distinguishes "one login attempt" from "an automated script trying 30 pairs in under a second." Query `login_events` and confirm you can see all 30 attempts land, unthrottled:

```sql
SELECT COUNT(*) FROM login_events WHERE occurred_at >= datetime('now', '-1 minute');
```

Paste this proof into `challenge-01.md`.

## Part 2 — Design and build the defense

You choose the exact thresholds — defend your choices in the write-up. At minimum, implement:

1. **Per-account lockout** using the `failed_attempts` / `locked_until` columns already in your `users` table (Exercise 1's schema) — after N consecutive failures, lock the account for a cooldown window, and check `locked_until` before even attempting a password comparison.
2. **Per-IP rate limiting** — independent of which account is being targeted, since a stuffing attacker rotates through *many* usernames from one source. A simple in-memory or SQLite-backed sliding window (e.g., "no more than 20 login attempts from one `source_ip` per minute") is sufficient for this lab; note in your write-up what you'd reach for in production (Redis-backed rate limiting, a WAF rule, or a managed service) and why an in-process solution doesn't survive multiple app instances.
3. **A response that doesn't leak which half was wrong.** Confirm your `/login` route returns the same generic `"invalid credentials"` for both "unknown user" and "wrong password" — Lecture 1 didn't say this explicitly, but think about *why* a login form that says "no such user" vs. "wrong password" as two different messages hands a stuffing attacker free account enumeration. Fix it if yours doesn't already.

## Part 3 — Prove the defense against your own attack

Re-run `stuffing_attack.py` unmodified against the defended app. **Expected:** the run now gets throttled or locked out partway through — paste the actual output showing where it started failing closed instead of open. Then answer in `challenge-01.md`: does your defense affect **grace's legitimate next login** if she tries again five minutes later? Prove it — log in as her for real after the cooldown window and confirm it succeeds.

## Part 4 — Detect it in SQL, without watching the script run

Using Lecture 1, Section 7's queries as a starting point, write a **single SQL query** against `login_events` that would flag this exact attack pattern — one source IP, many distinct usernames, in a short window — **without you already knowing an attack happened.** Run it against your logged data and confirm it correctly identifies your script's source IP.

## Constraints

- The defense must be provably effective against the **exact script you wrote in Part 1** — "I believe this would work" is not sufficient; "I ran the same script and here's the output showing it failed" is.
- State your chosen thresholds (lockout count, cooldown duration, rate-limit window) and justify each in one sentence — too strict locks out real users on a bad Wi-Fi day, too loose doesn't stop the attack.
- Don't forget Lecture 1, Section 6's spraying variant in your write-up: briefly explain why a *very* patient attacker trying one common password across many accounts, spread over hours, would slip under a naive per-IP-per-minute threshold — and what additional signal (Challenge 2's territory, and a fair thing to simply name rather than build here) would catch it.

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|---------------|
| Attack | Described, not run | `stuffing_attack.py` actually executed with pasted output |
| Defense | "Added a rate limiter" | Specific thresholds stated, justified, and proven with a before/after run |
| False positives | Ignored | Explicitly proves the legitimate user isn't permanently locked out |
| Detection | Assumes the SQL from the lecture works unchanged | Ran the query against real logged data and confirmed it flags the actual attack |
| Spraying awareness | Not mentioned | Names the gap and what closing it would require |

## Submission

Commit `stuffing_attack.py`, your updated `app.py`, and `challenge-01.md` (with all pasted proof) to your portfolio under `c50-week-04/challenge-01/`.
