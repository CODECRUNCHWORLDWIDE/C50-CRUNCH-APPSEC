# Exercise 1 — Fix Broken Object-Level Authorization

**Goal:** Reproduce the BOLA on `GET /api/v1/tasks/<id>`, capture the evidence, fix it at the source, and re-test in both directions.

**Estimated time:** 90 minutes.

## Before you start

`crunch-tasks-api` running (`python3 app.py`), seeded (`python3 seed.py`), and reachable at `http://127.0.0.1:5000`. Have both lab tokens handy: `tok_alice_LABONLY_0001` (role `user`) and `tok_bob_LABONLY_0002` (role `admin`).

## Task 1 — Confirm the seed data

```bash
sqlite3 crunchtasks.db "SELECT id, user_id, title FROM tasks;"
```

You should see three tasks: two owned by user 1 (alice) and one owned by user 2 (bob). Write down which task ID belongs to which user — you'll reference these exact IDs in every command below.

## Task 2 — Demonstrate the BOLA

Confirm Alice can read her own task first (this should succeed and is **not** the bug — it's your control case):

```bash
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/1
```

Now have Alice read Bob's task (the one owned by user 2) using her own token:

```bash
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/3
```

Save both full requests and responses into `evidence-bola.md`. The second response returning Bob's task body — instead of a 404 — is your proof of the flaw. Note the exact task title and body text you were never supposed to see; you'll reference it in the re-test.

## Task 3 — Remediate

Open `app.py` and find `get_task`. Add the ownership predicate directly to the query — do **not** fetch first and check ownership in a separate `if` afterward; put it in the `WHERE` clause itself, exactly as Lecture 1 demonstrated:

```python
@app.route("/api/v1/tasks/<task_id>")
def get_task(task_id):
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    row = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user["id"]),
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
```

Restart the app (`python3 app.py`) so the fix takes effect.

## Task 4 — Re-test, both directions

**The attack must now fail:**

```bash
curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/3
```

Expect a `404` with `{"error":"not found"}` — **not** a `403`. Explain in `evidence-bola.md`, in your own words, why 404 (rather than a more "honest-sounding" 403) is the correct response here.

**The legitimate case must still work:**

```bash
# alice reading her own task must still succeed
curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/1

# bob reading his own task must still succeed
curl -s -w "\nHTTP %{http_code}\n" -H "Authorization: Bearer tok_bob_LABONLY_0002" \
  http://127.0.0.1:5000/api/v1/tasks/3
```

Both must return `200` with the correct task body. Append all three re-test transcripts to `evidence-bola.md`.

## Done when…

- [ ] `evidence-bola.md` contains the original attack (succeeding), the fix diff, and all three re-test transcripts.
- [ ] The cross-user read now returns `404`, never `403`.
- [ ] Both legitimate owners can still read their own tasks after the fix.
- [ ] You can explain, in one sentence, why the ownership check belongs in the `WHERE` clause rather than in an `if` statement applied to the fetched row.

## Stretch

- `crunch-tasks-api` also has an unfixed BOLA-adjacent gap: nothing stops a caller from *guessing* valid task IDs at all (there's no rate limit on this endpoint either). Note this down — Lecture 2's rate-limiting section and Challenge 1 both come back to it.
- Write a second, negative test: confirm requesting a task ID that doesn't exist at all (e.g., `/api/v1/tasks/9999`) also returns a clean `404`, not a `500` — a malformed or missing task should never crash the route.

## Submission

Commit your fixed `app.py` and `evidence-bola.md` to your portfolio under `c50-week-09/exercise-01/`. Exercise 2 continues editing this same `app.py` — don't start a fresh copy.
