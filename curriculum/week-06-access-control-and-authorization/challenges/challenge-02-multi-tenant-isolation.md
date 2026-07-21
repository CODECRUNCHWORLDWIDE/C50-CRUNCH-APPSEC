# Challenge 2 — Enforce Multi-Tenant Isolation

**Time:** ~90 minutes. **Difficulty:** Medium-hard. **This is a systematic audit, not a single bug hunt.**

## The scenario

Exercises 1–3 fixed the IDOR on `/tickets/<id>` and the roster route, and locked function-level access with RBAC. It would be easy to declare victory on multi-tenancy at this point — but Lecture 1, Section 4 was explicit that the tenant check is a **mandatory floor that runs before any role or ownership logic, on every route**, and nothing so far has actually *proven* that floor holds everywhere. This challenge makes you build the proof, systematically, the way a real access-control audit works — and it will very likely turn up at least one route the exercises didn't touch.

## Your task

### Part 1 — Enumerate every route that touches company-scoped data

Before writing any test, list **every** `crunch-helpdesk` route in `routes.md`, and for each, state in one sentence what tenant check it *should* have. Include routes the exercises already fixed (to confirm coverage) and routes you haven't specifically re-examined for tenant leakage yet — in particular, look hard at any route that takes **two** identifiers where a mismatch between them could cross a tenant boundary (a ticket ID plus a target user ID, for instance), not just routes with a single ID in the URL.

### Part 2 — Build a systematic cross-tenant fuzz

Write `tenant_fuzz.py`: for every route in your Part 1 list that returns or modifies a specific object, try it with **every account from Company A against every plausible object ID belonging to Company B**, and vice versa. Structure it as data, not one-off `curl` calls:

```python
import sqlite3
import requests

BASE = "http://127.0.0.1:5000"
PASSWORD = "labpass1"

CRUNCH_CORP_USERS = ["cc-alice", "cc-bob", "cc-carol", "cc-dave"]
APERTURE_USERS    = ["al-erin", "al-frank", "al-grace", "al-heidi"]
CRUNCH_CORP_TICKETS = [1, 2, 3]
APERTURE_TICKETS    = [4, 5]

sessions = {}
def get_session(username):
    if username not in sessions:
        s = requests.Session()
        s.post(f"{BASE}/login", data={"username": username, "password": PASSWORD})
        sessions[username] = s
    return sessions[username]

db = sqlite3.connect("tenant_fuzz_results.db")
db.execute("""CREATE TABLE IF NOT EXISTS tenant_fuzz_results (
    id INTEGER PRIMARY KEY, username TEXT, route TEXT, method TEXT,
    target TEXT, status_code INTEGER, leaked BOOLEAN, checked_at TEXT DEFAULT (datetime('now')))""")

def probe(username, method, route, target_desc, data=None):
    s = get_session(username)
    resp = s.request(method, f"{BASE}{route}", data=data)
    leaked = resp.status_code == 200   # any 200 across a tenant boundary IS a leak, full stop
    db.execute(
        "INSERT INTO tenant_fuzz_results (username, route, method, target, status_code, leaked) VALUES (?,?,?,?,?,?)",
        (username, route, method, target_desc, resp.status_code, leaked),
    )
    return resp

# Cross-tenant ticket reads — every crunch-corp user against every aperture ticket, and reverse
for user in CRUNCH_CORP_USERS:
    for ticket_id in APERTURE_TICKETS:
        probe(user, "GET", f"/tickets/{ticket_id}", f"aperture ticket {ticket_id}")
for user in APERTURE_USERS:
    for ticket_id in CRUNCH_CORP_TICKETS:
        probe(user, "GET", f"/tickets/{ticket_id}", f"crunch-corp ticket {ticket_id}")

# Cross-tenant reassignment — the two-identifier case Part 1 flagged: does reassigning
# a ticket check BOTH that the ticket and the target assignee are in-company?
probe("cc-carol", "POST", "/tickets/4/reassign", "aperture ticket -> crunch-corp assignee",
      data={"assigned_to": "1"})
probe("al-grace", "POST", "/tickets/1/reassign", "crunch-corp ticket -> aperture assignee",
      data={"assigned_to": "5"})

# Cross-tenant roster reads
for user in CRUNCH_CORP_USERS:
    probe(user, "GET", "/companies/2/roster", "aperture-labs roster")
for user in APERTURE_USERS:
    probe(user, "GET", "/companies/1/roster", "crunch-corp roster")

db.commit()
db.close()
```

Extend this scaffold to cover **every** route from your Part 1 list, not just the ones shown above — the point of the challenge is your own thoroughness, not filling in a template.

### Part 3 — Query for leaks

```sql
SELECT username, route, method, target, status_code
FROM tenant_fuzz_results
WHERE leaked = 1
ORDER BY route;
```

If this returns zero rows on your first run, you likely didn't test the two-identifier case in Part 1's hint closely enough — go back and specifically fuzz `/tickets/<id>/reassign` with a ticket from one company and an `assigned_to` user from the other, checked in **both** directions (Company A ticket → Company B assignee, and the reverse). A route can pass "does this ticket belong to my company" and still leak by writing a foreign-company user ID into a same-company ticket's `assigned_to` column.

### Part 4 — Fix every real leak, then re-run the entire fuzz

For each leak found, apply the same tenant-check pattern from Lecture 1, Section 4 and Exercise 1/2 — checking **all** identifiers a route accepts, not just the one in the URL path. Re-run `tenant_fuzz.py` in full afterward (not just the previously-failing probes) and confirm `SELECT COUNT(*) FROM tenant_fuzz_results WHERE leaked = 1` is `0`.

## Constraints

- A route that returns `404` instead of `403` across a tenant boundary is **not** a leak (Lecture 2, Section 4's uniform-404 pattern) — only a `200` that hands back real cross-tenant data or performs a real cross-tenant mutation counts.
- Fuzz **both directions** for every pair (Company A against Company B, and Company B against Company A) — a fix that only closes one direction is not a fix.
- Do not hand-pick "safe" IDs to test — cover the full grid described in Part 2, including at least one `admin`-vs-`admin` cross-tenant probe (the highest-privilege role is exactly the one most likely to have a check silently skipped, "because they're an admin, it's probably fine").

## Hints

<details>
<summary>If you can't find a real leak anywhere</summary>

Look specifically at `/tickets/<id>/reassign` after Exercise 2's fix. `@require_permission("ticket:reassign")` proves the **caller's role** can reassign tickets — it says nothing about whether the **ticket itself** belongs to the caller's company, or whether the **new assignee** does. Two identifiers, two potential tenant checks, and it's easy to add only one.

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|---|---|---|
| Route enumeration | Only lists routes already fixed by the exercises | Complete list, including the two-identifier reassignment case |
| Fuzz coverage | Tests one direction, a handful of IDs | Both directions, full account × object grid, admin included |
| Leak found | None found because coverage was too narrow | Finds the reassignment gap (or another real one) with evidence |
| Fix | Patches only the specific probe that failed | Checks every identifier the route accepts, re-verified with a full re-run |

## Submission

Commit `routes.md`, `tenant_fuzz.py`, `tenant_fuzz_results.db`, and the updated `app.py` to your portfolio under `c50-week-06/challenge-02/`. This fuzz harness is the direct ancestor of the mini-project's full proof matrix.
