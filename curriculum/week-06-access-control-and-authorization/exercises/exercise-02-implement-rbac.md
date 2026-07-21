# Exercise 2 — Implement RBAC on an Endpoint Set

**Goal:** Build the role-permission matrix from Lecture 1 as real tables in `crunchhelpdesk.db`, write the reusable `@require_permission` decorator, and apply it to every `crunch-helpdesk` route currently missing a function-level authorization check — proving each fix by demonstrating the exact vertical-escalation request from Lecture 3 now fails.

**Estimated time:** 90 minutes.

## Setup

```bash
cd c50-week-06/exercise-01/crunch-helpdesk    # continue from Exercise 1's fixed app.py
```

## Task 1 — Add the RBAC tables

Append to `schema.sql` (or a new `rbac_schema.sql` you load after the base schema):

```sql
CREATE TABLE roles (
    role_name TEXT PRIMARY KEY
);

CREATE TABLE permissions (
    permission_name TEXT PRIMARY KEY
);

CREATE TABLE role_permissions (
    role_name       TEXT NOT NULL REFERENCES roles(role_name),
    permission_name TEXT NOT NULL REFERENCES permissions(permission_name),
    PRIMARY KEY (role_name, permission_name)
);
```

Load Lecture 1, Section 2.1's full matrix (all four roles, all seven permissions, every grant row) — copy it verbatim from the lecture, don't re-derive it from scratch, so your matrix matches the policy this week actually specified:

```bash
sqlite3 crunchhelpdesk.db < rbac_schema.sql
sqlite3 crunchhelpdesk.db < rbac_seed.sql   # your INSERT statements from Lecture 1, Section 2.1
```

Verify with a query before writing any Python:

```bash
sqlite3 crunchhelpdesk.db "SELECT role_name, permission_name FROM role_permissions ORDER BY role_name;"
```

## Task 2 — Write `require_permission`

Add to `app.py` (Lecture 1, Section 2.1's decorator, plus the `_declares_permission` marker Lecture 3, Section 4.1 needs later):

```python
from functools import wraps

def require_permission(permission_name):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "role" not in session:
                return jsonify(error="login required"), 401
            allowed = get_db().execute(
                "SELECT EXISTS (SELECT 1 FROM role_permissions "
                "WHERE role_name = ? AND permission_name = ?)",
                (session["role"], permission_name),
            ).fetchone()[0]
            if not allowed:
                return jsonify(error="forbidden"), 403
            return view_func(*args, **kwargs)
        wrapped._declares_permission = True
        return wrapped
    return decorator
```

## Task 3 — Apply it to every route missing a function-level check

Go route by route through `app.py` and, for each, run Lecture 3 Section 5's four-question checklist. Apply `@require_permission` to close question 2 wherever it currently fails:

```python
@app.route("/tickets", methods=["POST"])
@require_permission("ticket:create")
def create_ticket():
    ...

@app.route("/tickets/<ticket_id>/reassign", methods=["POST"])
@require_permission("ticket:reassign")
def reassign_ticket(ticket_id):
    ...

@app.route("/admin/users")
@require_permission("roster:view")
def admin_users():
    ...

@app.route("/admin/users/<user_id>/promote", methods=["POST"])
@require_permission("user:promote")
def promote_user(user_id):
    target = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        return jsonify(error="not found"), 404
    if target["company_id"] != session["company_id"]:   # Lecture 3, Section 3 — role check alone isn't enough
        return jsonify(error="forbidden"), 403
    new_role = request.form["role"]
    get_db().execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    get_db().commit()
    return jsonify(message=f"user {user_id} promoted to {new_role}")

@app.route("/companies/<company_id>/roster")
@require_permission("roster:view")
def company_roster(company_id):
    if int(company_id) != session["company_id"]:
        return jsonify(error="forbidden"), 403
    rows = get_db().execute(
        "SELECT id, username, role FROM users WHERE company_id = ?", (session["company_id"],)
    ).fetchall()
    return jsonify([dict(r) for r in rows])
```

`/tickets` (`GET`, list) and `/tickets/<id>` (`GET`, single) keep their Exercise 1 ownership-filtered queries — those are object-level checks, not function-level ones, and every role is allowed to *attempt* viewing tickets; the query itself scopes *which* tickets. Don't add `@require_permission` where the real fix is already the `WHERE`-clause filter from Exercise 1.

## Task 4 — Re-test every vertical-escalation path from Lecture 3

Restart `app.py`, then re-run, exactly as written, the exploit requests from Lecture 3 Sections 2 and 3:

```bash
curl -s -c cc-alice.txt -X POST http://127.0.0.1:5000/login -d "username=cc-alice&password=labpass1"

# member reassigning a ticket — must now be 403
curl -s -i -b cc-alice.txt -X POST http://127.0.0.1:5000/tickets/2/reassign -d "assigned_to=1"

# member listing all users — must now be 403
curl -s -i -b cc-alice.txt http://127.0.0.1:5000/admin/users
```

Then confirm the **legitimate** path still works — `cc-dave` (admin, crunch-corp) promoting `cc-alice` (also crunch-corp) should still succeed:

```bash
curl -s -c cc-dave.txt -X POST http://127.0.0.1:5000/login -d "username=cc-dave&password=labpass1"
curl -s -i -b cc-dave.txt -X POST http://127.0.0.1:5000/admin/users/1/promote -d "role=agent"
```

And confirm the cross-tenant half of that same route still correctly fails — `cc-dave` (crunch-corp admin) attempting to promote `al-erin` (aperture-labs, user id 5):

```bash
curl -s -i -b cc-dave.txt -X POST http://127.0.0.1:5000/admin/users/5/promote -d "role=admin"
# must be 403 — right role, wrong tenant
```

## Done when…

- [ ] `role_permissions` contains the full matrix from Lecture 1, and `SELECT role_name, permission_name FROM role_permissions WHERE role_name = 'agent'` returns exactly the three rows the lecture specified — nothing more, nothing less.
- [ ] Every route identified as "missing a function-level check" in this week's README table now carries `@require_permission`.
- [ ] `cc-alice` (member) gets `403` on reassign and on `/admin/users` — verified by a fresh request, not assumed.
- [ ] `cc-dave` (admin, crunch-corp) can promote a **crunch-corp** user but is correctly `403`'d promoting an **aperture-labs** user — proving the role check and the tenant check are both actually in force.
- [ ] You can name, from memory, which of `crunch-helpdesk`'s routes need only an RBAC gate, which need only an object/tenant check, and which need both.

## Stretch

- Add a fifth role, `readonly-auditor`, that can view (but never create, reassign, or promote) anything across **all** roles' visible tickets at their own company only. Add it to `roles`, grant it the right `view_*` permissions, and add one lab account with that role to prove it out.
- Wire in Lecture 3, Section 4.1's `before_request` deny-by-default hook. Temporarily comment out `@require_permission` on one route and confirm the hook now blocks it with a `403` instead of the route silently working — that's the structural check doing its job.

## Submission

Commit `app.py`, `rbac_schema.sql`, `rbac_seed.sql`, and `crunchhelpdesk.db` to your portfolio under `c50-week-06/exercise-02/`. Exercise 3 builds the systematic test matrix that proves this coverage holds across every role and every route, not just the ones you happened to re-test above.
