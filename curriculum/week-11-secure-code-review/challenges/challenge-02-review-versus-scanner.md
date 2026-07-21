# Challenge 2 — Review vs. Scanner Bake-Off

**Time:** ~90 minutes. **Difficulty:** Medium. **No fixed finding count — the comparison is the point.**

## The scenario

Week 8 taught you to run Semgrep against a codebase and triage what comes back. A natural question follows: **if a scanner can find vulnerabilities automatically, why did this entire week just have you do it by hand?** This challenge answers that honestly, with data from your own work, instead of an opinion. You already have a manual findings list for `crunch-invoices` from Exercise 3 and Challenge 1. Now run Semgrep against the same app and compare.

## Your task

### Step 1 — Run Semgrep against `crunch-invoices`

```bash
pip install semgrep
cd crunch-invoices
semgrep --config=auto --config=p/flask --config=p/sql-injection --config=p/secrets . --json --output semgrep-results.json
semgrep --config=auto --config=p/flask --config=p/sql-injection --config=p/secrets .
```

Save both the human-readable output and the JSON. Run it against the app with `PR #482` applied — the same state your manual review covered.

### Step 2 — Reconcile Semgrep's list against your manual findings list

Build a table in `challenge-02.md` with one row per **distinct issue** (yours, Semgrep's, or both), and these columns:

| Issue | Found by your review? | Found by Semgrep? | Notes |
|---|---|---|---|

Populate it with **every** row your `review_findings.db` (from Exercise 3 + Challenge 1) contains, cross-referenced against every distinct Semgrep result. You will likely see all four buckets represented:

- **Found by both** — Semgrep and you independently flagged the same line.
- **Found only by your review** — a flaw your taint tracing caught that Semgrep's output has no matching entry for.
- **Found only by Semgrep** — something the scanner flagged that your manual review missed or didn't get to.
- **Semgrep false positive** — something Semgrep flagged that, on inspection, isn't actually exploitable here (state precisely why, the way Week 8 taught you to justify a dismissal).

### Step 3 — Explain the gap, honestly

Answer, in `challenge-02.md`, with specific reference to your own table:

1. Which of your findings did Semgrep **also** catch, and for those, would a scanner alone (no human review) have been sufficient to ship this PR safely?
2. Which of your findings did Semgrep **miss**? Look specifically at the missing-authentication-check on `/invoices/search` and the missing-role-check on `/invoices/export` — can a generic SAST ruleset realistically be expected to know that `export_invoices` is *supposed* to check `session["role"]` and doesn't, when nothing about the code's syntax looks wrong? What would a rule need to "know" about this specific app's authorization model to catch it?
3. Did Semgrep flag anything you missed? If yes, what — and does it hold up as a real finding once you trace it, or is it a false positive? If Semgrep found nothing you missed, say so plainly rather than inventing a gap.
4. In one paragraph: which vulnerability **classes** is a scanner reliably good at (name at least two, with reasoning), and which classes does this exercise show it's structurally weak at (name at least one, with reasoning tied to *why* — not just "it missed it")?

## Constraints

- Run the scanner for real. A comparison table built from guessing what a scanner "probably" would find is not this challenge — the whole exercise is worthless without the actual `semgrep` output in front of you.
- Every "false positive" claim needs the same standard of evidence a real finding does: trace it, and explain specifically why it's not exploitable here.
- Don't undersell your own review to make the comparison flattering, and don't oversell it either — this challenge is only useful if the table is honest in both directions.

## Hints

<details>
<summary>On why authorization gaps are hard for SAST</summary>

A SAST tool matches patterns in code structure — it can reliably flag "this string is built with an f-string and passed to `execute()`" because that's a *syntactic* fact about the code, true regardless of what the app does. "This route is supposed to check the caller's role before returning data" is a *semantic* fact about your app's intended authorization model — the tool has no way to know that `export_invoices` was ever supposed to check anything beyond what generic rules already look for (like "is there any `session` check at all"), because nothing in the Flask route decorator or its body syntactically distinguishes "checks enough" from "checks too little." This is precisely why Lecture 1's five-question checklist exists as a *human* method: question 2 requires knowing the app's authorization model, not just its syntax.

</details>

## How success is judged

| Signal | Weak submission | Strong submission |
|---|---|---|
| Scanner run | Skipped, or output summarized without the actual file | Real `semgrep-results.json` present and referenced by specific finding IDs |
| Comparison table | Vague ("scanner found some stuff too") | Row-by-row, every finding from both sources accounted for |
| Honesty | Only reports where the review won | Reports scanner wins and false positives too, if any exist |
| Reasoning | "Scanners are good/bad" as a blanket claim | Ties each claim to a *specific* finding and *why* that class is easy or hard to detect syntactically |

## Submission

Commit `challenge-02.md` and `semgrep-results.json` to your portfolio under `c50-week-11/challenge-02/`.
