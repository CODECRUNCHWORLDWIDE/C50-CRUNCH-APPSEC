# Lecture 2 — Cryptographic Failures, Injection, and Insecure Design

> **Duration:** ~2 hours. **Outcome:** You can define A02, A03, and A04 precisely; recognize each as a code (or design) pattern; and you have demonstrated and fixed one representative flaw from each against `crunch-notes`.

These three categories are grouped together because they share the highest **blast radius** on the list — when any of them fails, the failure tends to be total (every password, every row in the database, every request the server can reach) rather than partial. They also illustrate three different *kinds* of root cause: A02 is a wrong algorithm choice, A03 is a wrong way of building a query string, and A04 is a missing requirement that no amount of careful coding would have caught, because the careful code was never asked to defend against it.

## 1. A02 — Cryptographic Failures

**Cryptographic failures** cover any case where sensitive data — passwords, tokens, personal data, session identifiers — is protected by cryptography that is missing, weak, misconfigured, or misused. In the 2017 list this was folded under the vaguer "Sensitive Data Exposure"; 2021 renamed it to name the actual root cause: exposure is the *symptom*, broken crypto is the *cause*.

Two failures live in `crunch-notes`, and they compound each other:

```python
app.config["SECRET_KEY"] = "dev"  # VULNERABLE — weak, hardcoded, committed to source

def md5(text):
    return hashlib.md5(text.encode()).hexdigest()  # VULNERABLE — fast, unsalted hash
```

**Why `md5()` for passwords is broken, specifically:**

- **MD5 is a fast, general-purpose hash, not a password hash.** It was designed for checksums and digital signatures, where speed is a feature. For passwords, speed is the vulnerability: a modern GPU computes billions of MD5 hashes per second, so an attacker who steals the `users` table can brute-force every short or common password in minutes.
- **No salt.** Every user with the password `"password123"` gets the *identical* hash. An attacker doesn't even need to brute-force per-user — a single precomputed table of common-password hashes (a "rainbow table") cracks every matching account in the database at once.
- **The correct tool is a slow, salted, purpose-built password hash** — `bcrypt`, `scrypt`, or `argon2` — that deliberately costs milliseconds of CPU time per guess instead of nanoseconds, and includes a random salt automatically so identical passwords never produce identical hashes.

**Why the hardcoded `SECRET_KEY` matters:** Flask uses `SECRET_KEY` to cryptographically **sign** the session cookie, so a client can't forge or tamper with it. `"dev"` is a string that appears in thousands of public tutorials and, worse, is committed to source control here — anyone who reads the repo (or finds it in a leaked backup, or a Git history search) can forge a valid, signed session cookie for *any* user ID, no password required.

**Demonstrate the weak hashing** — show that the stored hash is trivially reversible with a public, free tool:

```bash
# what's actually stored for alice's password ("alice-pass")?
python3 -c "import hashlib; print(hashlib.md5(b'alice-pass').hexdigest())"
# a6b4b8b3a3b3d5e2c1f0a9b8c7d6e5f4  (illustrative — run it yourself to see the real value)
```

Paste that hash into any free online MD5 lookup, or crack it locally in your isolated lab with a wordlist:

```bash
# entirely local, no network egress, in your own venv
pip install argon2-cffi  # you'll want this for the fix below anyway
echo "alice-pass" > wordlist.txt
python3 - <<'EOF'
import hashlib
target = hashlib.md5(b"alice-pass").hexdigest()
with open("wordlist.txt") as f:
    for line in f:
        guess = line.strip()
        if hashlib.md5(guess.encode()).hexdigest() == target:
            print(f"cracked: {guess}")
EOF
```

This tiny script is the entire idea behind every real password-cracking tool, just without the speed optimizations — which is precisely why "how fast can it be guessed" is the property that matters for a password hash, and why MD5 fails that property by design.

**Remediate it** with `werkzeug.security` (already a Flask dependency) or `argon2-cffi`:

```python
from werkzeug.security import generate_password_hash, check_password_hash

# at signup / seed time:
password_hash = generate_password_hash("alice-pass")  # salted, slow, algorithm-tagged

# at login time:
if row is None or not check_password_hash(row["password_hash"], password):
    return jsonify(error="invalid credentials"), 401
```

And fix the secret key by generating a real random one and loading it from the environment, never from source:

```python
import os
app.config["SECRET_KEY"] = os.environ["CRUNCH_NOTES_SECRET_KEY"]  # set once, per environment
```

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # generate it once
export CRUNCH_NOTES_SECRET_KEY=<paste the output>            # set it in your shell, never in git
```

**Re-test:** re-seed with the new hashing (`generate_password_hash`), confirm `/login` still succeeds with the correct password and still fails with the wrong one, and confirm `python3 -c "..."` no longer finds a matching MD5 hash for any password in the wordlist — because the stored value is no longer an MD5 hash at all.

## 2. A03 — Injection

**Injection** happens when untrusted input is passed to an interpreter — a SQL engine, a shell, an OS command runner, an LDAP query, a template engine — in a way that lets the input change the *structure* of the command instead of just supplying a *value* inside it. SQL injection is the most common form and `crunch-notes`'s `/search` route has a clean example:

```python
@app.route("/search")
def search_notes():
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    q = request.args.get("q", "")
    db = get_db()
    # VULNERABLE (A03) — query built by string formatting, not parameterized: SQL injection
    sql = f"SELECT id, title FROM notes WHERE user_id = {session['user_id']} AND title LIKE '%{q}%'"
    rows = db.execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])
```

The database cannot tell the difference between "text the developer wrote" and "text a user supplied" once they've been concatenated into the same string — it just sees one SQL statement and executes it. A crafted `q` value can close the intended `'...'` string early and add its own SQL:

**Demonstrate it:**

```bash
# normal use: search alice's own notes for "budget"
curl -s -b alice.txt "http://127.0.0.1:5000/search?q=budget"

# injection: close the LIKE string, add OR 1=1 to match every row regardless of user_id
curl -s -b alice.txt --data-urlencode "q=%' OR '1'='1" -G http://127.0.0.1:5000/search
```

The crafted `q` turns the query into `... AND title LIKE '%%' OR '1'='1'` — a condition that's always true for every row in the table, not just Alice's. The `WHERE user_id = {session['user_id']}` guard Lecture 1 might make you assume protects this is defeated too, because `OR '1'='1'` short-circuits the entire clause. With a slightly more aggressive payload (`' UNION SELECT username, password_hash FROM users --`), the same flaw can be used to pull data out of a completely different table — this is why SQL injection routinely ranks as one of the highest-impact categories on the list: one string-formatting mistake can expose the entire database, not just the one table the endpoint was meant to query.

**Remediate it** — the fix is *always* the same shape: never build a query by inserting values into a string; always let the database driver bind them as parameters:

```python
@app.route("/search")
def search_notes():
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        "SELECT id, title FROM notes WHERE user_id = ? AND title LIKE ?",
        (session["user_id"], f"%{q}%"),
    ).fetchall()
    return jsonify([dict(r) for r in rows])
```

The `?` placeholders tell SQLite "these are values, never interpret them as SQL syntax" — the database itself enforces the boundary between code and data that string formatting erased. This is a stronger guarantee than trying to "sanitize" or escape the input yourself: escaping requires you to correctly anticipate every dangerous character for every context, forever; parameterization removes the entire class of mistake.

**Re-test:** re-run the exact injection payload from above. It must now return an empty result (`[]`) rather than every row in the database — the `'` in the payload is now treated as a literal character to search for in a title, not as SQL syntax.

## 3. A04 — Insecure Design

**Insecure design** is the newest category on the 2021 list, and it's conceptually different from every other category here: it's not a coding mistake at all. The code can be implemented flawlessly and still be insecure, because the **security requirement itself was never written down** — nobody, at design time, asked "what happens if this gets abused?" This is exactly the gap Week 2's STRIDE threat modeling exists to close, one design decision earlier than "insecure design" catches it as a finding.

`crunch-notes`'s export feature is a clean, small example:

```python
@app.route("/notes/export")
def export_notes():
    # VULNERABLE (A04) — insecure design: no pagination and no size cap were ever designed in
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    rows = db.execute(
        "SELECT title, body FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    blob = "\n\n".join(f"# {r['title']}\n{r['body']}" for r in rows)
    return blob, 200, {"Content-Type": "text/plain"}
```

There's no SQL injection here — the query is parameterized correctly. There's no access-control bug — it correctly scopes to `session["user_id"]`. And yet it's insecure: **nothing anywhere in the schema, the route, or the request handling limits how many notes a user can have, how large a single note's `body` can be, or how much data one request to `/export` can generate.** A user (or a compromised account) that creates ten million one-megabyte notes turns a single `GET /notes/export` into a multi-gigabyte in-memory string build and response — a self-inflicted denial-of-service that no amount of "careful coding" of this specific route would have prevented, because the missing control lives upstream of it, at the point notes are created and stored.

**Demonstrate the missing constraint:**

```bash
# nothing stops an oversized note from being created — there's no length check anywhere
python3 - <<'EOF'
import requests
big_body = "x" * 5_000_000   # 5 MB in one note
r = requests.post(
    "http://127.0.0.1:5000/notes",  # (add a create-note route for this drill, or insert directly via sqlite3)
)
EOF
# or, more directly, insert straight into the seeded db to prove the schema itself has no limit:
python3 -c "
import sqlite3
db = sqlite3.connect('crunchnotes.db')
db.execute(\"INSERT INTO notes (user_id, title, body) VALUES (1, 'huge', ?)\", ('x' * 5_000_000,))
db.commit()
print('inserted a 5MB note with zero pushback from the schema')
"
```

That insert succeeds silently — proof that the *design* never included a limit, not that one particular route forgot to check one.

**Remediate it at the design level, not just the route level** — the fix has to live in the schema and be enforced everywhere notes are created, not patched into `/export` alone:

```sql
-- schema.sql, corrected: a real constraint, enforced by the database itself
CREATE TABLE notes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    title      TEXT NOT NULL CHECK (length(title) <= 200),
    body       TEXT NOT NULL CHECK (length(body) <= 20000),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

And add an application-level cap on the export endpoint itself, so even a legitimately large *number* of small notes can't blow up one request:

```python
@app.route("/notes/export")
def export_notes():
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    rows = db.execute(
        "SELECT title, body FROM notes WHERE user_id = ? ORDER BY id LIMIT 200",
        (session["user_id"],),
    ).fetchall()
    blob = "\n\n".join(f"# {r['title']}\n{r['body']}" for r in rows)
    return blob, 200, {"Content-Type": "text/plain"}
```

**Re-test:** re-run the direct-insert attempt above against the corrected schema — SQLite must now raise `sqlite3.IntegrityError: CHECK constraint failed: notes` and refuse the insert. Then confirm `/notes/export` still works normally for a user with a reasonable number of ordinary-sized notes.

## 4. Why these three are grouped, and what's different about A04

A02 and A03 are both "you wrote the wrong code" — a specific line is fixable with a specific, well-known correct pattern (a real password hash, a parameterized query). A04 is "nobody wrote a requirement" — the fix required going back to the schema and asking a question ("what's the maximum reasonable size of a note?") that a code reviewer reading the `/export` route in isolation would never have thought to ask, because the route itself is implemented correctly. This is exactly why Week 2's threat modeling happens *before* code is written: STRIDE's "Denial of Service" category, applied to the `notes` data store during design, would have surfaced "what stops unbounded growth?" as a question before a single line of `/export` existed.

## 5. Check yourself

- Why is MD5 unsuitable for password storage even though it's cryptographically fine for, say, verifying a downloaded file's checksum?
- What specific property does parameterization give you that string-escaping doesn't?
- Rewrite, in your own words, why the `/search` injection payload `' OR '1'='1` returns every row instead of zero.
- Give one example of an insecure-design flaw (not from this lecture) where the code implementing a feature could be perfectly correct and the feature would still be dangerous.
- Why does the A04 fix require a schema change (`CHECK` constraint) instead of just a check inside one route handler?

Lecture 3 covers the remaining seven categories — misconfiguration, vulnerable components, authentication failures, integrity failures, logging gaps, and SSRF — each with the same demonstrate-and-fix treatment, at survey depth.

## Further reading

- **OWASP Top 10:2021 — A02 Cryptographic Failures:** <https://owasp.org/Top10/A02_2021-Cryptographic_Failures/>
- **OWASP Top 10:2021 — A03 Injection:** <https://owasp.org/Top10/A03_2021-Injection/>
- **OWASP Top 10:2021 — A04 Insecure Design:** <https://owasp.org/Top10/A04_2021-Insecure_Design/>
- **OWASP Cheat Sheet — Password Storage:** <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- **OWASP Cheat Sheet — SQL Injection Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
