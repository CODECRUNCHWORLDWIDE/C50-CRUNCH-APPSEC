# Exercise 1 — Break and Fix Password Storage

**Goal:** Build `crunch-authlab` v0 exactly as broken as Lecture 1, Sections 2–3 describe — plaintext passwords — prove how cheap that is to exploit, then rebuild storage on argon2id and prove the same attack now fails.

**Estimated time:** 90 minutes.

**Scope:** Everything below runs against `crunch-authlab`, a Flask app you are about to write and run on `127.0.0.1:5000`. Every account is fictional, created by you, for this exercise only.

## Setup

Inside `~/appsec-lab/crunch-authlab/` (see [exercises/README.md](./README.md) for the venv setup), create `schema.sql`:

```sql
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS login_events;

CREATE TABLE users (
    user_id         INTEGER PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,     -- v0: this column is a LIE — it's plaintext. Fixed in Task 4.
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT
);

CREATE TABLE login_events (
    event_id    INTEGER PRIMARY KEY,
    username    TEXT NOT NULL,
    event_type  TEXT NOT NULL,          -- 'success' | 'bad_password' | 'unknown_user'
    source_ip   TEXT NOT NULL,
    occurred_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO users (username, password_hash) VALUES
  ('grace', 'CorrectHorseBattery1'),
  ('ada',   'letmein123'),
  ('alan',  'qwerty2024'),
  ('linus', 'p@ssw0rd!');
```

Load it: `sqlite3 authlab.db < schema.sql`

Now create `app.py` — **v0, deliberately broken**, matching Lecture 1 Sections 2–3 and Lecture 3's Section 3 bug on purpose (that one's for Exercise 3 — leave it as-is for now):

```python
"""
crunch-authlab v0 — DELIBERATELY BROKEN, lab use only.
Fictional accounts, localhost only. Never deploy this code anywhere real.
"""
import sqlite3
import time
from flask import Flask, request, redirect, make_response, g

DB_PATH = "authlab.db"
app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_event(username, event_type, ip):
    db = get_db()
    db.execute(
        "INSERT INTO login_events (username, event_type, source_ip) VALUES (?, ?, ?)",
        (username, event_type, ip),
    )
    db.commit()


LOGIN_FORM = """
<form method="post">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Log in</button>
</form>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_FORM

    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if row is None:
        log_event(username, "unknown_user", request.remote_addr)
        return "invalid credentials", 401

    # BUG — fixed in Task 4: plaintext comparison, no hashing at all.
    if password != row["password_hash"]:
        log_event(username, "bad_password", request.remote_addr)
        return "invalid credentials", 401

    log_event(username, "success", request.remote_addr)
    # BUG — fixed in Exercise 3: guessable session id, no cookie flags.
    session_id = f"{username}-{int(time.time())}"
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session_id", session_id)
    return resp


@app.route("/dashboard")
def dashboard():
    session_id = request.cookies.get("session_id", "")
    username = session_id.split("-")[0] if "-" in session_id else None
    if not username:
        return redirect("/login")
    return f"Welcome, {username}."


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
```

Run it: `python app.py`, then in a browser visit `http://127.0.0.1:5000/login` and confirm you can log in as `grace` / `CorrectHorseBattery1`.

Save a copy as `app_v0.py` before you touch anything — the mini-project compares versions.

## Tasks

### Task 1 — Dump the database, no cracking required

With the app running (or stopped, doesn't matter — it's your own SQLite file), run:

```bash
sqlite3 authlab.db "SELECT username, password_hash FROM users;"
```

**Expected:** every password is sitting there in the clear. Write one sentence in `writeup.md`: what does this prove about the *cost* of "cracking" a plaintext-stored password database?

### Task 2 — The counterfactual: what if it had been SHA-256?

Create `wordlist.txt` with 25 common passwords, including the four real ones from `schema.sql` mixed in among decoys (`123456`, `password`, `dragon`, `monkey`, `iloveyou`, `qwerty2024`, `letmein123`, `CorrectHorseBattery1`, `p@ssw0rd!`, plus 17 more of your choosing).

Create `crack_demo.py`:

```python
import hashlib
import sqlite3
import time

def sha256_hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()

def crack_sha256(target_hash: str, wordlist_path: str) -> str | None:
    with open(wordlist_path) as f:
        for line in f:
            guess = line.strip()
            if sha256_hash(guess) == target_hash:
                return guess
    return None

if __name__ == "__main__":
    db = sqlite3.connect("authlab.db")
    users = db.execute("SELECT username, password_hash FROM users").fetchall()

    print("Simulating: what if these had been SHA-256 hashed instead of plaintext?")
    start = time.perf_counter()
    for username, plaintext in users:
        fake_hash = sha256_hash(plaintext)              # what the column WOULD hold under SHA-256
        cracked = crack_sha256(fake_hash, "wordlist.txt")
        status = f"CRACKED: {cracked!r}" if cracked else "not in wordlist"
        print(f"  {username}: {status}")
    elapsed = time.perf_counter() - start
    print(f"\nAll {len(users)} accounts attacked in {elapsed*1000:.3f} ms")
```

Run it: `python crack_demo.py`. **Expected:** all four accounts crack, total time under a few milliseconds. Add the timing to `writeup.md`.

### Task 3 — Time a single argon2id hash for comparison

```bash
pip install argon2-cffi   # if not already installed in Task setup
python3 -c "
import time
from argon2 import PasswordHasher
ph = PasswordHasher()
start = time.perf_counter()
ph.hash('CorrectHorseBattery1')
print(f'{(time.perf_counter() - start) * 1000:.1f} ms for ONE argon2id hash')
"
```

**Expected:** somewhere in the 100–500ms range (hardware-dependent) — roughly **100,000× to 1,000,000× slower per guess** than the SHA-256 loop in Task 2. In `writeup.md`, do the arithmetic: if cracking all 4 SHA-256 hashes against your 25-word list took the time you measured in Task 2, roughly how long would the same 25-word attack take per hash against argon2id? (Multiply your per-hash argon2id time by 25.) State the number.

### Task 4 — Fix it: rebuild storage on argon2id

Edit `app.py`:

1. Add the hashing functions from Lecture 1, Section 4.1:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

ph = PasswordHasher()

def hash_password(plaintext: str) -> str:
    return ph.hash(plaintext)

def verify_password(stored_hash: str, plaintext: str) -> bool:
    try:
        ph.verify(stored_hash, plaintext)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
```

2. Write `migrate_to_argon2.py` to rehash every existing plaintext row **in place**:

```python
import sqlite3
from app import hash_password

db = sqlite3.connect("authlab.db")
rows = db.execute("SELECT user_id, password_hash FROM users").fetchall()
for user_id, current in rows:
    if not current.startswith("$argon2"):
        db.execute(
            "UPDATE users SET password_hash = ? WHERE user_id = ?",
            (hash_password(current), user_id),
        )
db.commit()
print("Migration complete.")
```

Run it: `python migrate_to_argon2.py`, then re-run Task 1's dump query. **Expected:** every `password_hash` now starts with `$argon2id$…`.

3. Replace the login route's plaintext comparison:

```python
    # was: if password != row["password_hash"]:
    if not verify_password(row["password_hash"], password):
        log_event(username, "bad_password", request.remote_addr)
        return "invalid credentials", 401
```

Restart the app and confirm `grace` / `CorrectHorseBattery1` still logs in successfully — the *user experience* is unchanged; only the storage and comparison changed.

### Task 5 — Prove the fix against the original attack

Re-run `crack_demo.py` unmodified. **Expected:** it still "cracks" instantly — because it's still simulating a *hypothetical* SHA-256 column, not reading your real (now-argon2id) database. That's the point: change `crack_demo.py` to read the **real** `password_hash` column instead of re-hashing with SHA-256, and try to run the same dictionary loop against it with `hashlib.sha256(...) == target_hash` — it will never match, because the stored value isn't a SHA-256 hash at all anymore. Write one sentence in `writeup.md`: why does a SHA-256 dictionary attack script fail outright against an argon2id hash, before you even get to the speed difference?

Save the final file as `app_v1.py`.

## Done when…

- [ ] `app_v0.py` exists and is genuinely plaintext (Task 1's dump proves it).
- [ ] `writeup.md` has the Task 1 sentence, the Task 2 timing, the Task 3 arithmetic, and the Task 5 sentence.
- [ ] `migrate_to_argon2.py` runs cleanly and every row in `users` starts with `$argon2id$`.
- [ ] `app_v1.py` uses `verify_password()`, not `==`, and `grace` can still log in with her original password.
- [ ] You can explain, without looking back at the lecture, why `ph.hash()` produces a *different* string every time you hash the same password.

## Stretch

- Add `ph.check_needs_rehash(stored_hash)` to the login route (Lecture 1, Section 4.2) so a future cost-parameter bump re-hashes automatically on next login.
- Time a dictionary attack against a **bcrypt**-hashed version of the same passwords (`pip install bcrypt`) and compare to your argon2id number.

## Submission

Commit `app_v0.py`, `app_v1.py`, `schema.sql`, `crack_demo.py`, `migrate_to_argon2.py`, `wordlist.txt`, and `writeup.md` to your portfolio under `c50-week-04/exercise-01/`.
