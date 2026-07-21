# Exercise 3 — Build an Authorization Test Matrix

**Goal:** Replace "I re-tested the two or three requests I remembered to check" with a systematic, data-driven suite that tries **every role against every resource-and-action combination** and records pass/fail as queryable rows — the only method that actually proves coverage instead of sampling it.

**Estimated time:** 90 minutes.

## Why manual re-testing isn't enough

Exercise 2's Task 4 re-tested exactly the requests Lecture 3 happened to demonstrate. That's necessary but not sufficient — it proves the two or three paths you thought to check are fixed, and says nothing about the combinations you didn't think of: does an `agent` at `aperture-labs` get correctly blocked from `crunch-corp`'s roster? Does a `manager` get correctly blocked from `/admin/users/<id>/promote`? With 4 roles × 2 companies × 8 users × 7 routes, there are dozens of meaningful combinations — far more than anyone reliably re-tests by hand, and exactly why this course's data-tooling rule insists this becomes a real table, generated and checked by code, not a mental checklist.

## Setup

```bash
cd c50-week-06/exercise-02/crunch-helpdesk    # continue from Exercise 2
```

## Task 1 — Design the results schema

```sql
CREATE TABLE authz_test_results (
    result_id       INTEGER PRIMARY KEY,
    username        TEXT NOT NULL,
    role            TEXT NOT NULL,
    company         TEXT NOT NULL,
    route           TEXT NOT NULL,
    method          TEXT NOT NULL,
    target_resource TEXT,              -- e.g. 'ticket 4 (aperture-labs)'
    expected_status TEXT NOT NULL CHECK (expected_status IN ('allow','deny')),
    actual_status   INTEGER NOT NULL,
    passed          BOOLEAN NOT NULL,
    run_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
```

```bash
sqlite3 test_results.db "$(cat <<'SQL'
CREATE TABLE authz_test_results (
    result_id       INTEGER PRIMARY KEY,
    username        TEXT NOT NULL,
    role            TEXT NOT NULL,
    company         TEXT NOT NULL,
    route           TEXT NOT NULL,
    method          TEXT NOT NULL,
    target_resource TEXT,
    expected_status TEXT NOT NULL CHECK (expected_status IN ('allow','deny')),
    actual_status   INTEGER NOT NULL,
    passed          BOOLEAN NOT NULL,
    run_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
SQL
)"
```

## Task 2 — Write the expected-outcome matrix, by hand, before running anything

This is the important step, and it must come **before** you write the test runner: decide, on paper, what *should* happen for every combination, straight from Lecture 1's permission table and the tenant rule — so you're testing against your own written policy, not against whatever the code currently happens to do.

Create `expected_matrix.py` as a plain data structure:

```python
# (username, route, method, target_resource, expected)
# expected is 'allow' or 'deny', decided from the Lecture 1 policy table + tenant rule,
# written BEFORE running any test.
EXPECTED = [
    # Own-company ticket view — every role should be able to view own/assigned/in-scope tickets
    ("cc-alice", "/tickets/3", "GET", None, "allow"),     # alice created it
    ("cc-bob",   "/tickets/1", "GET", None, "allow"),     # bob is assigned
    ("cc-alice", "/tickets/2", "GET", None, "deny"),      # alice, not owner/assignee/manager
    ("cc-carol", "/tickets/2", "GET", None, "allow"),     # carol is manager, company-wide view
    # Cross-tenant ticket view — must ALWAYS deny, regardless of role
    ("cc-dave",  "/tickets/4", "GET", None, "deny"),      # admin, but wrong company
    ("al-heidi", "/tickets/1", "GET", None, "deny"),      # admin, but wrong company
    # Reassignment — manager/admin only, same company
    ("cc-alice", "/tickets/2/reassign", "POST", "assigned_to=1", "deny"),   # member
    ("cc-bob",   "/tickets/2/reassign", "POST", "assigned_to=1", "deny"),   # agent
    ("cc-carol", "/tickets/2/reassign", "POST", "assigned_to=1", "allow"),  # manager
    # Admin roster — manager/admin only
    ("cc-alice", "/admin/users", "GET", None, "deny"),     # member
    ("cc-carol", "/admin/users", "GET", None, "allow"),    # manager
    # Promotion — admin only, same company
    ("cc-carol", "/admin/users/1/promote", "POST", "role=agent", "deny"),   # manager, not admin
    ("cc-dave",  "/admin/users/1/promote", "POST", "role=agent", "allow"),  # admin, same company
    ("cc-dave",  "/admin/users/5/promote", "POST", "role=admin", "deny"),   # admin, WRONG company
    # Roster IDOR — must always match session company
    ("cc-carol", "/companies/2/roster", "GET", None, "deny"),   # manager, wrong company
    ("cc-carol", "/companies/1/roster", "GET", None, "allow"),  # manager, own company
]
```

Sixteen rows is a floor, not a target — **extend this to at least 24** by adding the `aperture-labs` mirror of each `crunch-corp` case (proving the tenant boundary holds in both directions, not just one) and at least one case per remaining route this week touched.

## Task 3 — Write the test runner

```python
import sqlite3
import requests

from expected_matrix import EXPECTED

BASE = "http://127.0.0.1:5000"
PASSWORD = "labpass1"

USER_INFO = {   # username -> (role, company) — for the results table, not the request itself
    "cc-alice": ("member", "crunch-corp"), "cc-bob": ("agent", "crunch-corp"),
    "cc-carol": ("manager", "crunch-corp"), "cc-dave": ("admin", "crunch-corp"),
    "al-erin": ("member", "aperture-labs"), "al-frank": ("agent", "aperture-labs"),
    "al-grace": ("manager", "aperture-labs"), "al-heidi": ("admin", "aperture-labs"),
}

db = sqlite3.connect("test_results.db")
sessions = {}

def get_session(username):
    if username not in sessions:
        s = requests.Session()
        s.post(f"{BASE}/login", data={"username": username, "password": PASSWORD})
        sessions[username] = s
    return sessions[username]

for username, route, method, body, expected in EXPECTED:
    s = get_session(username)
    data = dict(pair.split("=") for pair in body.split("&")) if body else None
    resp = s.request(method, f"{BASE}{route}", data=data)

    passed_allow = expected == "allow" and resp.status_code == 200
    passed_deny  = expected == "deny" and resp.status_code in (401, 403, 404)
    passed = passed_allow or passed_deny

    role, company = USER_INFO[username]
    db.execute(
        """INSERT INTO authz_test_results
           (username, role, company, route, method, target_resource,
            expected_status, actual_status, passed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (username, role, company, route, method, body, expected, resp.status_code, passed),
    )
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {username} ({role}/{company}) {method} {route} -> {resp.status_code} (expected {expected})")

db.commit()
db.close()
```

Run it against your Exercise 2 `app.py` (still running on `127.0.0.1:5000`):

```bash
pip install requests
python3 run_matrix.py
```

## Task 4 — Query for gaps

```sql
-- Every failure, with enough context to go fix it
SELECT username, role, company, route, method, expected_status, actual_status
FROM authz_test_results WHERE passed = 0;

-- Pass rate by route — which route has the most trouble?
SELECT route, COUNT(*) AS total, SUM(passed) AS passed, ROUND(100.0 * SUM(passed) / COUNT(*), 1) AS pass_pct
FROM authz_test_results GROUP BY route ORDER BY pass_pct ASC;

-- Pass rate by role — does one role fail disproportionately?
SELECT role, COUNT(*) AS total, SUM(passed) AS passed
FROM authz_test_results GROUP BY role;
```

## Task 5 — Fix any real failures, then re-run the whole matrix

If Task 4 turns up a real gap (not a mistake in your `expected_matrix.py` itself — double check the policy table first), fix it in `app.py` exactly as Exercises 1–2 did, then **re-run the entire matrix from scratch**, not just the failing rows — a fix for one route can accidentally affect another if they share a decorator or helper function.

## Done when…

- [ ] `expected_matrix.py` has **at least 24 rows**, covering both companies, all four roles, and at least six distinct routes.
- [ ] `python3 run_matrix.py` runs clean and every row in `authz_test_results` has `passed = 1`.
- [ ] All three queries in Task 4 run; the "every failure" query returns zero rows on your final run.
- [ ] You can explain, for at least two rows, *why* the expected outcome is `allow` or `deny` — tying it back to Lecture 1's permission table or the tenant rule, not just "the test says so."

## Stretch

- Parameterize the runner so it can also test `PUT`/`DELETE` verbs once you add ticket-editing routes in the mini-project — the matrix pattern should outlive this exercise's specific route list.
- Add a `regression` flag: re-run the full matrix after any future change to `app.py` and alert (print, at minimum) if any previously-passing row now fails — the shape of a real CI authorization test.

## Submission

Commit `expected_matrix.py`, `run_matrix.py`, `test_results.db`, and your Task 4 query output to your portfolio under `c50-week-06/exercise-03/`. This exact matrix, extended, is the backbone of this week's mini-project.
