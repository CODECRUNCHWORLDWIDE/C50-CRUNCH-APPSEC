# Exercise 2 — Add TOTP MFA to a Login

**Goal:** Turn `crunch-authlab`'s single-step login (Exercise 1's `app_v1.py`) into the two-step state machine from Lecture 2, Section 6 — password, then TOTP — with hashed recovery codes and a session that genuinely cannot reach `/dashboard` between the two steps.

**Estimated time:** 90 minutes.

**Scope:** Your own account in your own app, `127.0.0.1:5000`. Install a free authenticator app on your own phone or use a CLI TOTP generator (`resources.md` links both) — you are enrolling **yourself**, not a real third party.

## Setup

Continue from `app_v1.py`. Install `pyotp`: `pip install pyotp`.

Extend `schema.sql` (or run these as `ALTER TABLE` statements against your existing `authlab.db` — don't drop your migrated argon2id data):

```sql
ALTER TABLE users ADD COLUMN totp_secret TEXT;         -- NULL until enrolled
ALTER TABLE users ADD COLUMN mfa_enrolled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE recovery_codes (
    code_id   INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL,
    code_hash TEXT    NOT NULL,
    used_at   TEXT
);

CREATE TABLE pending_sessions (
    session_id   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    -- deliberately NOT the same table as an authenticated session (Exercise 3) —
    -- a pending session can ONLY reach the MFA-verification endpoint.
);
```

## Tasks

### Task 1 — Enrollment

Add an enrollment route. For this exercise, gate it behind a already-logged-in-with-password state (real products usually require re-entering the password before letting a user change MFA settings — note that in your write-up as a design detail, but don't build it, to keep scope tight):

```python
import pyotp
import secrets
from argon2 import PasswordHasher

ph = PasswordHasher()

@app.route("/enroll-mfa/<username>")
def enroll_mfa(username):
    db = get_db()
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Crunch AppSec Lab")
    db.execute("UPDATE users SET totp_secret = ?, mfa_enrolled = 1 WHERE username = ?", (secret, username))
    db.commit()

    codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(8)]
    user_id = db.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()["user_id"]
    for code in codes:
        db.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            (user_id, ph.hash(code)),
        )
    db.commit()

    return (
        f"<p>Secret (manual entry): <code>{secret}</code></p>"
        f"<p>Or add this URI to your authenticator app: <code>{uri}</code></p>"
        f"<p>Recovery codes (SAVE THESE — shown once): {', '.join(codes)}</p>"
    )
```

Visit `/enroll-mfa/grace`, add the secret to an authenticator app (or a CLI tool — see `resources.md`), and save the 8 recovery codes somewhere in your notes.

### Task 2 — Rewire login into the two-step state machine

Replace the `/login` route's post-password section:

```python
    log_event(username, "success", request.remote_addr)

    if row["mfa_enrolled"]:
        pending_id = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO pending_sessions (session_id, user_id) VALUES (?, ?)",
            (pending_id, row["user_id"]),
        )
        db.commit()
        resp = make_response(redirect("/mfa"))
        resp.set_cookie("pending_id", pending_id, httponly=True)   # NOT session_id — cannot reach /dashboard
        return resp

    # no MFA enrolled — fall back to Exercise 1's session issuance (unchanged for now, Exercise 3 fixes this path too)
    session_id = f"{username}-{int(time.time())}"
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session_id", session_id)
    return resp
```

Add the MFA verification route:

```python
MFA_FORM = """<form method="post"><input name="code" placeholder="6-digit code or recovery code"><button>Verify</button></form>"""

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if request.method == "GET":
        return MFA_FORM

    pending_id = request.cookies.get("pending_id", "")
    db = get_db()
    pending = db.execute(
        "SELECT * FROM pending_sessions WHERE session_id = ?", (pending_id,)
    ).fetchone()
    if pending is None:
        return "no pending login — start over", 401

    user = db.execute("SELECT * FROM users WHERE user_id = ?", (pending["user_id"],)).fetchone()
    submitted = request.form["code"]
    totp = pyotp.TOTP(user["totp_secret"])

    ok = totp.verify(submitted, valid_window=1)
    if not ok:
        ok = try_recovery_code(db, user["user_id"], submitted)   # Task 3

    if not ok:
        log_event(user["username"], "mfa_fail", request.remote_addr)
        return "invalid code", 401

    log_event(user["username"], "mfa_success", request.remote_addr)
    db.execute("DELETE FROM pending_sessions WHERE session_id = ?", (pending_id,))
    db.commit()

    session_id = f"{user['username']}-{int(time.time())}"   # Exercise 3 replaces this
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session_id", session_id)
    resp.delete_cookie("pending_id")
    return resp
```

### Task 3 — Recovery codes, single-use

```python
def try_recovery_code(db, user_id, submitted_code):
    rows = db.execute(
        "SELECT code_id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user_id,),
    ).fetchall()
    for row in rows:
        try:
            ph.verify(row["code_hash"], submitted_code)
            db.execute(
                "UPDATE recovery_codes SET used_at = datetime('now') WHERE code_id = ?",
                (row["code_id"],),
            )
            db.commit()
            return True
        except Exception:
            continue
    return False
```

### Task 4 — Prove the state machine actually enforces the gate

With `grace` MFA-enrolled, log in with her correct password and stop **before** entering the TOTP code. In a second browser tab (or `curl` with the `pending_id` cookie you captured), try to visit `/dashboard` directly.

**Expected:** `/dashboard` reads `request.cookies.get("session_id")`, which was never set by the password-only step — so it redirects to `/login`, not `/dashboard`. In `proof.md`, paste the response and explain in one sentence why a `pending_id` cookie alone can't reach `/dashboard`.

### Task 5 — Prove wrong codes fail and recovery codes are single-use

1. Submit a deliberately wrong 6-digit code at `/mfa`. **Expected:** `invalid code`, and a `mfa_fail` row in `login_events`.
2. Submit one of your saved recovery codes. **Expected:** it works, logs you in, and marks that code's `used_at`.
3. Submit the **same** recovery code again on a fresh login. **Expected:** it fails — confirm with `sqlite3 authlab.db "SELECT * FROM recovery_codes WHERE user_id = 1;"` that `used_at` is set and the second attempt found no unused row matching it.

Record all three outcomes in `proof.md`.

## Done when…

- [ ] `grace` has a working TOTP secret in an authenticator app and 8 saved recovery codes.
- [ ] A correct password with no TOTP code cannot reach `/dashboard` (Task 4, proven, not assumed).
- [ ] A wrong TOTP code is rejected and logged as `mfa_fail`.
- [ ] A recovery code works exactly once, never twice.
- [ ] `recovery_codes.code_hash` contains argon2id hashes, never plaintext codes — confirm with a direct `SELECT`.

## Stretch

- Add a per-`pending_id` rate limit on `/mfa` (e.g., 5 attempts before the pending session is force-expired) — a 6-digit TOTP code is only ~1,000,000 possibilities, small enough to matter online (Lecture 2, Section 2.2).
- Read the WebAuthn Guide link in `resources.md` and write 3 sentences comparing what you'd have to build differently for a hardware-key-based second factor versus the TOTP flow above.

## Submission

Commit your updated `app.py` (save as `app_v2.py`), the schema additions, and `proof.md` to your portfolio under `c50-week-04/exercise-02/`. Do **not** commit your real TOTP secret or recovery codes if this repo is ever public — regenerate fresh ones for the lab account before committing, or note in `proof.md` that you rotated them after testing.
