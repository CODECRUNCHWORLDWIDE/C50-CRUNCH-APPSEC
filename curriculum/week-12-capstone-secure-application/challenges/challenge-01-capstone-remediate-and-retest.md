# Challenge 1 — Remediate and Re-Test Everything

Exercise 3 left you with a triaged `capstone_findings` backlog and, almost certainly, at least one open finding that isn't one of the eleven numbered vulnerabilities — the business-logic gap Lecture 3 previewed, a Bandit finding you deferred, or something your own manual review turned up. This challenge closes the backlog completely, or accepts what's left over with a justification that would survive being read aloud to a stranger.

**Estimated time:** 2 hours.

## The task

1. Re-run Exercise 3 Task 5's triage query. Every row it returns is your starting backlog.
2. For each `open` finding, in priority order (critical first), do one of two things:
   - **Fix it at the source**, then re-test with the same method that originally found it (re-run the DAST probe check, re-run Bandit, re-run the manual review item), and update its `capstone_findings` row to `status = 'retested_ok'` with `retested_at` set and `fix_description` filled in.
   - **Accept it**, only if you can answer all four of Lecture 3 Section 8's questions in writing, and set `status = 'wont_fix'` with the full justification in `notes`.
3. Specifically close the manager-approving-their-own-expense gap, if it's still open: add an ownership check to `approve_expense` so a manager (or admin) cannot approve an expense where `session["user_id"] == expense["user_id"]`, and re-test both the blocked case (self-approval) and the still-allowed case (approving someone else's expense).

```python
@app.route("/admin/approve/<expense_id>", methods=["POST"])
@require_role("manager", "admin")
def approve_expense(expense_id):
    row = get_db().execute("SELECT * FROM expenses WHERE id = ?", (expense_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    if row["user_id"] == session["user_id"]:
        return jsonify(error="cannot approve your own expense"), 403
    get_db().execute(
        "UPDATE expenses SET status = 'approved' WHERE id = ?", (expense_id,)
    )
    get_db().commit()
    return jsonify(message=f"expense {expense_id} approved")
```

4. Re-run the full triage query one final time and confirm it returns **zero** `open` rows — every remaining row is either `retested_ok` or a justified `wont_fix`.

## Re-test evidence, not narrative

For every finding you close, the proof has to be a **repeatable check**, not a sentence. If a finding came from the DAST probe, extend or re-run the probe script and show its new output. If it came from Bandit, re-run Bandit and show the finding no longer appears (or, for a `wont_fix`, show it still appears with the justification attached). If it came from manual review, write the exact request or code inspection you performed to confirm the fix, in enough detail that someone else could repeat it and get the same result.

```bash
# example: closing the self-approval gap
curl -s -c mona.txt -X POST http://127.0.0.1:5100/login -d "username=cl-mona&password=labpass1"
curl -s -i -b mona.txt -X POST http://127.0.0.1:5100/admin/approve/3   # mona's own expense -- expect 403
curl -s -i -b mona.txt -X POST http://127.0.0.1:5100/admin/approve/1  # someone else's -- expect 200
```

## Done when…

- [ ] `SELECT COUNT(*) FROM capstone_findings WHERE status = 'open'` returns `0`.
- [ ] Every `retested_ok` row has a non-null `retested_at` and a `fix_description` that names the actual code change, not just "fixed."
- [ ] Every `wont_fix` row has a `notes` field that answers all four of Lecture 3 Section 8's questions, not just one or two.
- [ ] The self-approval gap is closed and both the blocked and still-allowed cases are re-tested and evidenced.
- [ ] You can, from memory, list every finding that's `wont_fix` and explain why in one sentence each — Challenge 2 will ask you to do exactly this, unprompted.

## Stretch

- Write one SQL query that joins `capstone_findings` back to `risk_register` (via `linked_risk_id`) and shows, per original STRIDE category, the count of open vs. closed findings — a single query that proves coverage across the whole threat model, not just the eleven known bugs.
- If you have time, add a lightweight regression test file (`tests/test_security.py`, using `pytest` + `requests` or Flask's test client) that encodes every DAST check as an actual automated test, so this challenge's re-tests become part of the CI pipeline's blocking test suite from Lecture 2 Section 6 — closing the loop between "we tested it once" and "it's tested on every future commit."

## Submission

Commit the final `app.py`, the fully updated `capstone_findings.db`, and a short `remediation-summary.md` (one line per finding: what it was, how it was closed or why it was accepted) to `c50-week-12/challenge-01/`. Challenge 2 is the design-defense conversation built on top of exactly this evidence.
