# Exercise 1 — Demonstrate an Access-Control Flaw

**Goal:** Independently reproduce both A01 flaws in `crunch-notes` — the IDOR and the missing function-level check — capture evidence for each, fix both at the source, and re-test to prove the fix.

**Estimated time:** 90 minutes.

## Before you start

Confirm `crunch-notes` is running with the seed data from the week README:

```bash
cd crunch-notes
python3 app.py &
curl -s -X POST http://127.0.0.1:5000/login -d "username=alice&password=alice-pass"
```

You should see `{"message":"welcome alice"}`. If not, re-run `python3 seed.py` and check `app.py` matches the README.

## Task 1 — Establish two authenticated sessions

You'll need both users' cookies for the rest of this exercise.

```bash
curl -s -c alice.txt -X POST http://127.0.0.1:5000/login -d "username=alice&password=alice-pass"
curl -s -c bob.txt   -X POST http://127.0.0.1:5000/login -d "username=bob&password=bob-pass"
```

Confirm each cookie jar works before moving on:

```bash
curl -s -b alice.txt http://127.0.0.1:5000/notes
curl -s -b bob.txt   http://127.0.0.1:5000/notes
```

## Task 2 — Demonstrate the IDOR on `/notes/<note_id>`

Alice owns note `1`; Bob owns note `2`. Prove, with Alice's session only, that she can read Bob's note.

1. Confirm Alice's own note loads normally: `curl -s -b alice.txt http://127.0.0.1:5000/notes/1`.
2. Request Bob's note **using Alice's cookie jar**: `curl -s -b alice.txt http://127.0.0.1:5000/notes/2`.
3. Save both the request and the full response body to `evidence-idor.md`, plus one sentence stating what should have happened instead (a 404, since Alice was never granted this note).

## Task 3 — Demonstrate the missing function-level check on `/admin/users`

Alice is a regular user (`role='user'` in `seed.py`). Prove she can still reach an admin-only endpoint.

1. Request the endpoint with Alice's cookie: `curl -s -b alice.txt http://127.0.0.1:5000/admin/users`.
2. Confirm the response includes Bob's `role: "admin"` — proof this isn't just "returns data," it's "returns *privileged* data to an unprivileged account."
3. Save the request and response to `evidence-missing-function-check.md`.

## Task 4 — Score both findings before you fix anything

Using Week 1/Week 2's risk = likelihood × impact scale (Lecture 2, Week 1), score each flaw and write the justification in your evidence files:

- **IDOR on `/notes/<note_id>`** — any logged-in user, no special access needed; exposes another specific user's data per guess. Score it and justify both numbers.
- **Missing role check on `/admin/users`** — any logged-in user; exposes the entire user table including roles, in one request. Score it and justify both numbers.

## Task 5 — Fix both at the source

Apply the two fixes from Lecture 1, Sections 4a and 4b, to your own `app.py`:

1. Add the `AND user_id = ?` predicate to `/notes/<note_id>`.
2. Add a `require_role("admin")` check to `/admin/users`.

Restart the app after editing (`Ctrl+C`, then `python3 app.py` again).

## Task 6 — Re-test both directions

For each fix, confirm **both** that the attack now fails and that the legitimate case still works:

```bash
# IDOR fix — must now fail for alice, still work for bob (its owner)
curl -s -b alice.txt http://127.0.0.1:5000/notes/2   # expect: {"error":"not found"}
curl -s -b bob.txt   http://127.0.0.1:5000/notes/2   # expect: bob's note, unchanged

# role-check fix — must now fail for alice, still work for bob (an admin)
curl -s -b alice.txt http://127.0.0.1:5000/admin/users   # expect: {"error":"forbidden"}
curl -s -b bob.txt   http://127.0.0.1:5000/admin/users   # expect: the user list, unchanged
```

Append the four re-test requests and responses to your evidence files.

## Expected result (spot checks)

- `evidence-idor.md` shows the successful attack (before the fix) and the blocked attempt plus a still-working owner request (after the fix).
- `evidence-missing-function-check.md` shows the same before/after pattern.
- Both findings have a written likelihood/impact score with justification.
- Neither fix broke the legitimate case for its own owner/admin.

## Done when…

- [ ] `evidence-idor.md` and `evidence-missing-function-check.md` both exist with request, response, risk score, and re-test evidence.
- [ ] Your `app.py` has both fixes applied and restarts cleanly.
- [ ] All four re-test commands from Task 6 produce the expected result.
- [ ] You can explain, in one sentence each, why 404 (not 403) is the right response for the IDOR fix, and why the role check has to happen on the server, not just be hidden in the client.

## Stretch

- Find a **third** place in `crunch-notes` where an object-level or function-level check might be missing that this exercise didn't point you to (hint: re-read `/admin/install-plugin`'s role check from Lecture 3 — is `username != "bob"` really equivalent to `role != "admin"`, and why might that distinction matter if a second admin account existed?).

## Submission

Commit `evidence-idor.md`, `evidence-missing-function-check.md`, and your updated `app.py` to your portfolio under `c50-week-03/exercise-01/`. Exercise 3 loads these two findings into a database.
