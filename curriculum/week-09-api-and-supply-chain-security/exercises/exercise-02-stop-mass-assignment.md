# Exercise 2 — Stop Mass Assignment

**Goal:** Reproduce both mass-assignment flaws in `crunch-tasks-api` (privilege escalation at registration, ownership/reward theft on task update), fix both with explicit field allowlists, and re-test.

**Estimated time:** 90 minutes.

## Before you start

`crunch-tasks-api` running with Exercise 1's BOLA fix already applied. Same two lab tokens as Exercise 1.

## Task 1 — Demonstrate mass assignment on registration

Register a brand-new account, deliberately including fields a signup form should never grant:

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"mallory","email":"mallory@crunch.io","password":"labpass1","role":"admin","credits":99999}'
```

Confirm what actually landed in the database:

```bash
sqlite3 crunchtasks.db "SELECT username, role, credits FROM users WHERE username = 'mallory';"
```

Save the request, the response, and the query output into `evidence-mass-assignment.md`. A brand-new, never-verified signup holding `role = admin` and `credits = 99999` is your proof.

## Task 2 — Demonstrate mass assignment on task update

Using Alice's token, PATCH a task that belongs to Bob (task 3), setting fields no legitimate update should ever touch:

```bash
curl -s -X PATCH -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "reward_cents": 500000}' \
  http://127.0.0.1:5000/api/v1/tasks/3
```

Wait — with Exercise 1's fix applied, this route now filters by `user_id = ?` in the `WHERE` clause of the *fetch*, but check whether `update_task` (a **different** route) got the same fix or is still vulnerable. Confirm with:

```bash
sqlite3 crunchtasks.db "SELECT id, user_id, reward_cents FROM tasks WHERE id = 3;"
```

If `user_id` changed to `1` and/or `reward_cents` changed to `500000`, you've confirmed the mass-assignment bug is independent of — and not fixed by — Exercise 1's BOLA fix. Record this clearly in `evidence-mass-assignment.md`: **two different vulnerabilities, two different fixes, even on the same route.**

## Task 3 — Remediate both

Reset the database first so you're testing against clean data:

```bash
python3 seed.py
```

In `app.py`, add explicit allowlists above your route definitions:

```python
ALLOWED_REGISTER_FIELDS = {"username", "email", "password"}
ALLOWED_TASK_UPDATE_FIELDS = {"title", "body", "is_complete"}
```

Fix `register`:

```python
@app.route("/api/v1/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    clean = {k: v for k, v in data.items() if k in ALLOWED_REGISTER_FIELDS}
    import secrets
    token = "tok_" + secrets.token_hex(12)
    db = get_db()
    db.execute(
        "INSERT INTO users (username, email, password_hash, api_token, role, credits) "
        "VALUES (?, ?, ?, ?, 'user', 0)",
        (clean.get("username"), clean.get("email"), sha256(clean.get("password", "")), token),
    )
    db.commit()
    return jsonify(message="registered", api_token=token), 201
```

Fix `update_task` — the allowlist **and** keep Exercise 1's ownership predicate, since both flaws live in this one function:

```python
@app.route("/api/v1/tasks/<task_id>", methods=["PATCH"])
def update_task(task_id):
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    data = request.get_json(force=True, silent=True) or {}
    clean = {k: v for k, v in data.items() if k in ALLOWED_TASK_UPDATE_FIELDS}
    if not clean:
        return jsonify(error="no updatable fields provided"), 400
    db = get_db()
    columns = ", ".join(f"{k} = ?" for k in clean.keys())
    db.execute(
        f"UPDATE tasks SET {columns} WHERE id = ? AND user_id = ?",
        (*clean.values(), task_id, user["id"]),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, user["id"])
    ).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)
```

Restart the app.

## Task 4 — Re-test, both directions

**Registration attack must now fail to grant privilege:**

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"mallory2","email":"mallory2@crunch.io","password":"labpass1","role":"admin","credits":99999}'
sqlite3 crunchtasks.db "SELECT username, role, credits FROM users WHERE username = 'mallory2';"
```

Expect `role = 'user'` and `credits = 0`, regardless of what the request body asked for.

**Task-update attack must now fail:**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PATCH -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "reward_cents": 500000}' \
  http://127.0.0.1:5000/api/v1/tasks/3
```

Expect a `400` — both keys in the body are outside the allowlist, so `clean` is empty.

**Legitimate updates must still work:**

```bash
curl -s -w "\nHTTP %{http_code}\n" -X PATCH -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  -H "Content-Type: application/json" \
  -d '{"title": "Renew SSL cert (done early)", "is_complete": true}' \
  http://127.0.0.1:5000/api/v1/tasks/1
```

Expect a `200` with the task's `title` and `is_complete` updated. Append every transcript to `evidence-mass-assignment.md`.

## Expected result (spot checks)

- `mallory2` (post-fix registration) has `role = 'user'`, `credits = 0`.
- Task 3's `user_id` and `reward_cents` are unchanged by the attack attempt after the fix.
- Task 1's `title` and `is_complete` **are** changed by the legitimate `PATCH`.

## Done when…

- [ ] `evidence-mass-assignment.md` documents both attacks succeeding pre-fix, the fix, and all re-tests post-fix.
- [ ] Both allowlists are explicit sets of field names — no route builds a query from `data.keys()`/`request.json.keys()` directly, anywhere in `app.py`.
- [ ] You can explain, in one sentence, why the task-update route needed *two* separate fixes (allowlist and ownership predicate) rather than one.

## Stretch

- Add a fourth field to `ALLOWED_TASK_UPDATE_FIELDS` — say, `reward_cents` — but only make it settable by a caller with `role == 'admin'` (a manager approving a bounty), not by the task's own owner. This is a small, self-contained taste of Week 6/9's role-based authorization layered on top of ownership-based authorization.
- Convert one of the two allowlists into a `marshmallow` schema (Lecture 2, Section 2) and confirm it rejects a wrong-typed field (e.g., `{"is_complete": "yes"}` instead of a real boolean) that the plain-dict allowlist would have let through unchanged.

## Submission

Commit your updated `app.py` and `evidence-mass-assignment.md` to your portfolio under `c50-week-09/exercise-02/`. Exercise 3 works from this same fixed `app.py`'s dependency list, not a fresh copy.
