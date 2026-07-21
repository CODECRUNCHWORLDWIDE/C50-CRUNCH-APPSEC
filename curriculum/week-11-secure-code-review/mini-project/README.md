# Mini-Project — Full Secure Code Review of `crunch-invoices`

> Run the complete four-step method from this week's lectures against the whole app, produce a prioritized findings report a developer could act on today, fix every finding at the source, and prove each fix with a retest — all tracked to resolution in `review_findings.db`. This is the week's capstone: not "find bugs," but "run the review, ship the report, close the loop."

**Estimated time:** 3–3.5 hours, best done Saturday after the exercises and both challenges.

A security review that stops at the findings report is half a job. The other half — the half that actually makes software safer — is confirming every finding gets fixed, and proving it with the same reproduction that found it in the first place. This mini-project takes you through both halves, end to end, on `crunch-invoices`.

---

## Deliverable

A directory in your portfolio `c50-week-11/mini-project/` containing:

1. `review-report.md` — the full four-step method (entry points, sinks, taint traces, control verification) run against the entire app, plus a prioritized findings summary (worst severity first).
2. `review_findings.db` — every finding from the whole review, `status` progressing from `open` to `retested_ok` as you fix each one (see Milestone 4).
3. `fixes/` — a directory holding the actual fixed `app.py` (or a diff against the `PR #482`-applied version) for every finding you close.
4. `notes.md` — a short reflection (see the end).

This mini-project **reuses** everything you already built in the exercises and Challenge 1 — you are not starting over. If your `review_findings.db` from Challenge 1 already has every finding from the whole app, extend it here rather than recreating it.

---

## What "full" means this time

By this point you've reviewed `PR #482` in three separate passes (Exercises 1–3) and the whole app once (Challenge 1). This mini-project asks for one more pass, done as a single coherent document instead of scattered across exercise files — the way you'd actually hand a review to a team:

### Part A — The review (60–75 min)

Assemble `review-report.md` from your existing work:

1. **Entry-point table** — all nine routes (reuse Challenge 1's, refresh it if the app has changed).
2. **Sink catalog** — every dangerous operation across the whole file.
3. **Taint traces** — all seven findings this week's lab app contains: the SQL injection, the missing authentication check on `/invoices/search`, the missing authorization check on `/invoices/export`, and the three independent crypto/secrets findings on the download-link routes (hardcoded key, homemade MD5 MAC, non-constant-time compare) — plus explicit "verified clean" notes for the four reviewed `main`-branch routes.
4. **Prioritized findings summary** — a table, worst severity first, of every real finding, each linking to its full write-up.

### Part B — Fix every finding at the source (75–90 min)

For **every** finding in `review_findings.db` with `status = 'open'`, write the actual fix in `crunch-invoices`'s `app.py`:

- Parameterize `search_invoices`/`build_search_query` (Lecture 2, Section 2's fix).
- Add `require_login()` to `search_invoices`.
- Add a role + account-filtered query to `export_invoices` (mirror `mark_paid`'s pattern).
- Replace `hashlib.md5(SIGNING_KEY + str(invoice_id))` with `hmac.new(SIGNING_KEY.encode(), str(invoice_id).encode(), hashlib.sha256).hexdigest()`.
- Load `SIGNING_KEY` from an environment variable (`os.environ["INVOICE_SIGNING_KEY"]`) instead of a source-level literal.
- Replace `sig == expected` with `hmac.compare_digest(sig, expected)`.

Commit the fixed file. Save a `git diff` (or a fresh unified diff against the `PR #482`-applied baseline) into `fixes/` for each finding, or one combined diff if you fix everything in one pass — either is fine, as long as every finding's fix is traceable to a real code change.

### Part C — Retest and close (30–45 min)

For **every** finding, re-run the **exact** reproduction command from its `review_findings` row against the now-fixed app, and confirm it no longer succeeds. Then:

```sql
UPDATE review_findings
SET status = 'retested_ok',
    fix_description = '<what you actually changed, one sentence>',
    resolved_at = datetime('now')
WHERE finding_id = <id>;
```

Do this one finding at a time, with the real retest output pasted into `review-report.md` next to the corresponding entry — not a batch update you ran on faith.

---

## Milestones

- **Milestone 1 (60 min):** `review-report.md` assembled — all four steps, all nine routes, all seven findings plus the four "verified clean" notes.
- **Milestone 2 (60 min):** Every finding fixed at the source; `git diff` saved per finding (or combined) in `fixes/`.
- **Milestone 3 (45 min):** Every finding retested against the fixed app, with real output; every row in `review_findings.db` updated to `retested_ok`.
- **Milestone 4 (30 min):** `notes.md` reflection, and a final sanity pass confirming `SELECT * FROM review_findings WHERE status != 'retested_ok'` returns **zero rows**.

---

## Rules

- **Every finding gets a real fix, not a mitigation you merely describe.** "I'd recommend parameterizing this" is a finding, not a fix; the actual `?`-placeholder query in `app.py` is a fix.
- **Every retest uses the finding's own stored reproduction**, unchanged, against the fixed app — not a new, easier test you invented after the fact.
- **No finding gets marked `retested_ok` without a pasted retest output.** A status update on faith defeats the entire point of tracking resolution in a database instead of a to-do list.
- **Fixing one finding must not silently reintroduce or mask another.** After all fixes are in, re-run the full `curl` sanity checks from Exercise 1 for `cr-nina` and `wh-priya` to confirm normal, legitimate access still works exactly as `main`-branch behavior intended.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Completeness of the review | 25% | All nine routes, full sink catalog, all seven findings, all four "verified clean" notes present |
| Quality of each finding | 20% | Every finding has all seven fields (Lecture 3), a real reproduction, a defensible severity |
| Fix correctness | 25% | Every fix follows the specific pattern this week's lectures taught (parameterized queries, `hmac` + `compare_digest`, env-loaded secret, role + account filters) |
| Retest rigor | 20% | Every finding retested with its own original reproduction; real output pasted, not asserted |
| Reflection | 10% | `notes.md` shows genuine engagement with the questions below, not one-line answers |

---

## Reflection (`notes.md`, ~250 words)

1. Which finding took the longest to fix correctly, and why — was the fix itself hard, or was confirming it didn't break something else the hard part?
2. Pick one finding and describe, specifically, how a scanner (Challenge 2) would or wouldn't have caught it, and why.
3. Of the five controls this week's checklist verifies (authn, authz, injection, crypto, secrets), which one do you now trust yourself to check fastest from cold code, and which one still takes real, deliberate effort?
4. If you had to review a PR this size again next week, what's the one step of the four-step method you'd be tempted to skip under deadline pressure — and what's the concrete cost of skipping it, based on what this PR actually contained?

---

## Why this matters

This mini-project is the shape of the actual job: someone opens a pull request, you read it with a method instead of a vibe, you write down what you find so precisely that fixing it takes no follow-up conversation, and then — critically — you don't walk away until every finding is proven closed. Do this once, thoroughly, on code small enough to hold in your head, and the same four steps scale to a review of a codebase you'll never fully memorize, which is exactly what Week 12's capstone (and every real review you'll ever run) actually looks like.

When done: push, then take the [quiz](../quiz.md) and start [Week 12 — Capstone: secure application](../../week-12-capstone-secure-application/).
