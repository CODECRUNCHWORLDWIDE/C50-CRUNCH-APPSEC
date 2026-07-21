# Challenge 1 — Close a Privilege-Escalation Path

**Time:** ~90 minutes. **Difficulty:** Medium-hard. **The bug is not marked.**

## The scenario

A teammate shipped a new `crunch-helpdesk` feature: agents and managers need to be able to close a resolved ticket. They copied an existing route as a starting point, wired up a decorator, and it "looks protected" — there's a `@require_permission` on it, same as every other locked-down route this week. Add it to your `app.py`:

```python
@app.route("/tickets/<ticket_id>/close", methods=["POST"])
@require_permission("ticket:view_own")
def close_ticket(ticket_id):
    get_db().execute("UPDATE tickets SET status = 'closed' WHERE id = ?", (ticket_id,))
    get_db().commit()
    return jsonify(message=f"ticket {ticket_id} closed")
```

Restart `app.py` with this route added. Your job: find out why "it has a decorator" doesn't mean "it's actually restricted to the right roles," and fix it properly.

## Your task

### Part 1 — Find the flaw by reading, then confirm it by testing

Do **not** start by guessing and poking randomly. Run Lecture 3, Section 5's four-question checklist against this exact route, in writing, in a file called `analysis.md`:

1. Authentication — checked?
2. Function-level authorization (RBAC) — checked, and against the **correct** permission for what this action actually does?
3. Object/tenant-level authorization — checked?
4. Fails closed on ambiguity?

One of these questions has an answer that looks right at a glance and isn't. Find it by comparing the permission name in the decorator against Lecture 1's actual role-permission matrix — not by assuming a decorator's presence means the check is correct.

Once you've identified the specific gap in `analysis.md`, confirm it experimentally: log in as `cc-alice` (role `member`) and attempt to close a ticket that should be well outside her reach.

```bash
curl -s -i -b cc-alice.txt -X POST http://127.0.0.1:5000/tickets/1/close
```

Record the exact response in `analysis.md` alongside your written diagnosis.

### Part 2 — Design the correct policy, in writing, before touching code

This route needs a policy that doesn't exist yet anywhere in `role_permissions` — closing a ticket isn't the same permission as viewing one. In `analysis.md`, write the correct rule as a sentence, then as data:

- **Who should be able to close a ticket?** (Hint: re-read this week's README permission table — `member` never appears in any row that implies changing ticket state; only `agent`, `manager`, and `admin` do, and Lecture 1's ABAC section already gives you the shape of "which specific ticket" an agent versus a manager should be scoped to.)
- Add the missing permission to your RBAC tables:

```sql
INSERT INTO permissions VALUES ('ticket:close');
INSERT INTO role_permissions VALUES
    ('agent', 'ticket:close'), ('manager', 'ticket:close'), ('admin', 'ticket:close');
```

### Part 3 — Fix the route completely

A corrected `@require_permission("ticket:close")` alone closes the *vertical* half but still leaves a gap: nothing yet stops an **agent** from closing a ticket they aren't assigned to, or a ticket at a different company. Fix the whole thing:

```python
@app.route("/tickets/<ticket_id>/close", methods=["POST"])
@require_permission("ticket:close")
def close_ticket(ticket_id):
    ticket = get_db().execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="not found"), 404
    if ticket["company_id"] != session["company_id"]:
        return jsonify(error="forbidden"), 403
    if session["role"] == "agent" and ticket["assigned_to"] != session["user_id"]:
        return jsonify(error="forbidden"), 403   # agents close only what they're assigned
    get_db().execute("UPDATE tickets SET status = 'closed' WHERE id = ?", (ticket_id,))
    get_db().commit()
    return jsonify(message=f"ticket {ticket_id} closed")
```

### Part 4 — Re-test and extend the matrix

Add at least six new rows to Exercise 3's `expected_matrix.py` covering this route: a `member` (deny), an unassigned `agent` (deny), the correctly-assigned `agent` (allow), a `manager` at the same company (allow), an `admin` at a different company (deny), and one `aperture-labs` mirror case. Re-run `run_matrix.py` and confirm all pass.

## Constraints

- Do not simply swap in `@require_permission("roster:view")` or any other existing permission as a shortcut — the fix must use a permission that correctly and specifically describes "closing a ticket," matching Part 2's written policy.
- The final route must pass all four of Lecture 3 Section 5's checklist questions, not just the one you originally found broken.

## Hints

<details>
<summary>If you're stuck finding the flaw in Part 1</summary>

Ask: which roles hold the `ticket:view_own` permission in your `role_permissions` table? Check with `SELECT role_name FROM role_permissions WHERE permission_name = 'ticket:view_own';`. Every role — including `member` — holds it, because Lecture 1's matrix grants basic viewing to everyone. A decorator checking that permission on a state-**changing** action (closing a ticket) is checking the wrong thing entirely: it correctly proves "this route requires *some* permission," and completely fails to prove "this route requires the *right* permission for what it does."

</details>

<details>
<summary>If you're unsure how to phrase the agent-vs-manager distinction in Part 2</summary>

This is exactly Lecture 1 Section 3.1's RBAC-plus-ABAC layering: RBAC (the permission grant) answers "can this role close tickets **at all**," and an object-level check answers "can this **specific** agent close **this specific** ticket" — an agent's scope is narrower (only their own assignments) than a manager's (anyone's, company-wide).

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|---|---|---|
| Diagnosis | "It needs more checks" | Names the exact wrong permission, explains why it passes a superficial glance, cites the query that proves it |
| Policy design | Ad hoc "just add manager" | Written policy sentence, then correctly modeled as a new permission + role grants |
| Fix completeness | Only swaps the permission name | Adds the agent-vs-manager object-level distinction and the tenant check, matching Part 3 |
| Test coverage | Re-tests only the one exploit found | Extends the matrix with the six-plus cases from Part 4, all passing |

## Submission

Commit `analysis.md`, the updated `app.py`, `rbac_seed.sql` (with the new permission and grants), and the extended `expected_matrix.py` / `test_results.db` to your portfolio under `c50-week-06/challenge-01/`.
