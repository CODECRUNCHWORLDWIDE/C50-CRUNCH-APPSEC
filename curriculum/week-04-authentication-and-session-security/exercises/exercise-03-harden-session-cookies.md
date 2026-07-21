# Exercise 3 — Harden Session Cookies

**Goal:** Replace `crunch-authlab`'s guessable, unverified session cookie with a real, database-backed session — unguessable ID, correct cookie flags, rotation on login, idle + absolute timeout, and a logout that actually invalidates server-side state. Prove each fix against the exact bug it closes.

**Estimated time:** 90 minutes.

**Scope:** `127.0.0.1:5000`, your own app and accounts, throughout.

## Setup

Continue from `app_v2.py` (Exercise 2). Add the real session table:

```sql
CREATE TABLE sessions (
    session_id   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

## Tasks

### Task 1 — Prove the current bug: the dashboard trusts the cookie, not a database

Before changing any code, prove exactly how bad `app_v2.py`'s `/dashboard` route is. It never checks the database — it just reads whatever username is embedded in the cookie string:

```bash
# You never logged in as "ada" in this request. You're just FORGING her cookie.
curl -v -b "session_id=ada-9999999999" http://127.0.0.1:5000/dashboard
```

**Expected:** `Welcome, ada.` — a full authentication bypass, with zero password or MFA involved, because the server never verified the cookie against anything. Write this down in `proof.md` as **Bug 1**: "the current session token is not a reference to server-side state — it's unverified, attacker-constructible input."

### Task 2 — Replace the session with an unguessable, database-backed one

```python
import secrets
from datetime import datetime, timedelta

IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=12)

def new_session_id() -> str:
    return secrets.token_urlsafe(32)

def create_session(db, user_id: int) -> str:
    sid = new_session_id()
    db.execute(
        "INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", (sid, user_id)
    )
    db.commit()
    return sid

def get_valid_session(db, session_id: str):
    row = db.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    if row is None:
        return None
    now = datetime.utcnow()
    last_seen = datetime.fromisoformat(row["last_seen_at"])
    created = datetime.fromisoformat(row["created_at"])
    if now - last_seen > IDLE_TIMEOUT or now - created > ABSOLUTE_TIMEOUT:
        db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        db.commit()
        return None
    db.execute(
        "UPDATE sessions SET last_seen_at = ? WHERE session_id = ?",
        (now.isoformat(), session_id),
    )
    db.commit()
    return row
```

### Task 3 — Wire it into login, MFA completion, and the dashboard — with cookie flags

Replace **every** place `app_v2.py` set `session_id = f"{username}-{int(time.time())}"` (the no-MFA login path and the end of `/mfa`) with:

```python
    sid = create_session(db, row["user_id"])          # or user["user_id"] in /mfa
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie(
        "session_id", sid,
        httponly=True, secure=True, samesite="Lax",
        max_age=int(IDLE_TIMEOUT.total_seconds()),
    )
    return resp
```

And replace `/dashboard` to actually check the database instead of parsing the cookie string:

```python
@app.route("/dashboard")
def dashboard():
    db = get_db()
    session = get_valid_session(db, request.cookies.get("session_id", ""))
    if session is None:
        return redirect("/login")
    user = db.execute("SELECT username FROM users WHERE user_id = ?", (session["user_id"],)).fetchone()
    return f"Welcome, {user['username']}."
```

**Re-run Task 1's exact `curl` command.** **Expected:** now `redirect to /login` (a `302`), because `ada-9999999999` matches no row in `sessions`. Add this to `proof.md` as **Bug 1 — fixed**.

> **Note on `secure=True` in local dev:** with `secure=True` set, `curl`/browsers will only send the cookie back over HTTPS — over plain local `http://127.0.0.1`, some clients still accept it for `127.0.0.1` as a documented exception, others don't. If your local testing breaks, it's fine to test with `secure=False` on `127.0.0.1` and note in `proof.md` that this flag is **mandatory** the moment the app sits behind real TLS — never ship `secure=False` to production.

### Task 4 — Fixation: prove the pre-login session ID is discarded, not upgraded

Confirm the login route (Task 3) calls `create_session()` — a brand-new row — rather than reusing any session ID that existed before login. Prove it:

```bash
# 1. Visit /login WITHOUT logging in — you get no session_id cookie at all in this app's design,
#    because /login (GET) never issues one. Confirm that with:
curl -v http://127.0.0.1:5000/login 2>&1 | grep -i set-cookie
# Expected: no Set-Cookie line — nothing to fixate onto pre-login.

# 2. Log in for real, capture the cookie Flask issues:
curl -v -c cookies.txt -d "username=grace&password=<her real password>" http://127.0.0.1:5000/login 2>&1 | grep -i set-cookie
```

In `proof.md`, explain in your own words why `crunch-authlab` was never actually vulnerable to *classic* pre-login fixation once `/login` (GET) stopped issuing any session cookie — and why that's a **stronger** guarantee than "rotate on login" alone (Lecture 3, Section 5): there's simply no pre-auth token for an attacker to plant in the first place.

### Task 5 — Idle timeout, proven

Temporarily set `IDLE_TIMEOUT = timedelta(seconds=10)` for testing. Log in, wait 15 seconds, then hit `/dashboard` with the same cookie. **Expected:** redirected to `/login` — the row was deleted by `get_valid_session`'s expiry check. Confirm with `sqlite3 authlab.db "SELECT * FROM sessions;"` that the row is gone. Restore `IDLE_TIMEOUT` to 30 minutes afterward and note the test in `proof.md`.

### Task 6 — A logout that actually logs out

Add:

```python
@app.route("/logout", methods=["POST"])
def logout():
    db = get_db()
    sid = request.cookies.get("session_id", "")
    db.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
    db.commit()
    resp = make_response(redirect("/login"))
    resp.delete_cookie("session_id")
    return resp
```

Log in, copy the `session_id` cookie value, log out, then replay the **old, copied** cookie against `/dashboard` directly (`curl -b "session_id=<copied value>" ...`). **Expected:** `redirect to /login` — the database row is gone, so the copied cookie is worthless, unlike a logout that only clears the browser's copy. Record this proof in `proof.md`.

## Done when…

- [ ] `proof.md` documents Bug 1 (forged-cookie bypass) both before and after the fix, with the actual `curl` output pasted for each.
- [ ] Every session issuance path uses `secrets.token_urlsafe(32)` via `create_session()` — none use `f"{username}-{timestamp}"` anymore.
- [ ] `/dashboard` and every other authenticated route check `sessions` in the database — none parse the cookie string for identity.
- [ ] You demonstrated idle timeout actually expiring a session (Task 5) and reverted the test timeout back to 30 minutes.
- [ ] `/logout` deletes the database row, and you proved a copied pre-logout cookie is rejected afterward.

## Stretch

- Add a `mfa_verified` column check so that even a fully-created `sessions` row from the no-MFA path can't be replayed to bypass a *later* MFA enrollment on the same account.
- Add the CSRF synchronizer token from Lecture 3, Section 6 to the `/logout` `POST` and any other state-changing route you've built this week.

## Submission

Commit the final `app.py` (save as `app_v3.py`) and `proof.md` to your portfolio under `c50-week-04/exercise-03/`. This is the version the mini-project's write-up compares back to `app_v0.py`.
