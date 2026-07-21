# Exercise 1 — Review a PR for Injection & Authorization

**Goal:** Cold-read `crunch-invoices`'s `PR #482` using Lecture 1's method — entry points, sinks, the five-question control checklist — flag every route you suspect of an injection or an authorization flaw, then confirm each suspicion against the running app. No fixing yet; that's next week's discipline, this week is finding and proving.

**Estimated time:** 90 minutes.

## Setup

```bash
cd crunch-invoices
source .venv/bin/activate
git status   # confirm you're on the reviewed baseline, pr-482.diff NOT yet applied
```

Do **not** apply the diff yet for Task 1. You are reviewing it as a diff first, the way a real pull request shows up in a review tool — reading changed lines, not a live app.

## Task 1 — Cold read, no running code (30 min)

Open `pr-482.diff` in a text editor (not a browser, not a diff-viewer that hides context — read the raw patch). For **each** of the three new routes it adds (`/invoices/search`, `/invoices/export`, `/invoices/download/<invoice_id>` plus its companion `/invoices/<invoice_id>/download-link`), write in `raw-notes.md`:

1. **What does this route do**, in one sentence, from reading the code alone?
2. **Does it call `require_login()` or `require_role(...)`** — quote the exact line, or write "no call found" if there isn't one.
3. **Is every SQL statement it touches built with `?` placeholders**, or does any part of the query come from an f-string, `.format()`, or string concatenation? Quote the exact line.
4. **Does any query filter by `account_id` matching `session["account_id"]`**, or could it return rows belonging to a different account?

Do this for all three routes before moving to Task 2 — resist the temptation to run the app first "just to check." The whole point of a cold read is proving you can find flaws from the source alone, the way a reviewer without a running instance of your PR still has to.

## Task 2 — State your suspicions precisely (15 min)

For each route, write one sentence in `raw-notes.md` under a `## Suspicions` heading, in this exact shape: **"I suspect `<route>` has a `<injection|authz|both>` flaw because `<the specific line and reasoning from Task 1>`."** A suspicion without a specific line quoted is not precise enough — go back and find the line.

You should end up with at least these three suspicion statements (word them in your own voice, but they should cover the same ground):

- A suspicion about `/invoices/search` covering **both** categories.
- A suspicion about `/invoices/export` covering authorization.
- A note on whether `/invoices/<id>/download-link` and `/invoices/download/<id>` have an injection or authz issue, or whether — read carefully — their flaw is actually neither of those two categories (hold that thought; Challenge 1 covers it, this exercise is scoped to injection and authz only).

## Task 3 — Apply the PR and confirm each suspicion (35 min)

```bash
git apply pr-482.diff
python3 app.py &
curl -s -c cr-nina.txt -X POST http://127.0.0.1:5050/login -d "username=cr-nina&password=labpass1"
```

For each suspicion from Task 2, run the request that would prove it true or false, and record the **actual** request and response in `raw-notes.md` under a `## Confirmed` heading:

1. **`/invoices/search` — no login, and injection.** Send a request with **no session cookie at all** and confirm it still returns data. Then send a request with a single-quote in `q` (`q=x' OR '1'='1`) and observe whether the result set changes shape (all rows vs. a real filtered match).
2. **`/invoices/export` — cross-account leak.** Log in as `cr-nina` (`crunch-retail`, role `member`) and confirm `GET /invoices/export` returns invoices belonging to `crunch-wholesale` (`account_id = 2`) as well as her own account's.
3. **The download-link routes.** Call `GET /invoices/1/download-link` while logged in, note the `sig` value returned, then call `GET /invoices/download/1?sig=<that value>` **without** any session cookie at all. Does it succeed? What does that tell you about whether this route enforces authentication or authorization at all, versus relying entirely on the signature?

## Done when…

- [ ] `raw-notes.md` has a Task-1 entry for all three routes, each with a quoted line (not a paraphrase) backing every "no call found" / "yes, filters by account_id" claim.
- [ ] Three (or more) precise suspicion statements, each naming a specific line.
- [ ] All three suspicions confirmed against the running app, with the **actual** request and response body pasted in — not "confirmed, works as expected."
- [ ] You can state, in one sentence each, why `/invoices/search`'s flaw is worse than it would be if it *only* lacked a login check, or *only* had the injection — i.e., why the combination compounds the severity.

## Stretch

- `/invoices/export`'s route is reachable by `cr-nina`, a `member`. Would a `billing_admin` from `crunch-wholesale` calling the same route also be over-privileged, even though they *are* a billing admin — just for the wrong account? Confirm with a second login.
- The reviewed `main`-branch routes (`/invoices`, `/invoices/<id>`, `/invoices` POST, `/invoices/<id>/mark-paid`) are **not** part of this PR. Skim them anyway and note, in one line each, which of the two categories (injection, authz) each one demonstrates handling *correctly* — this is your baseline for comparison in Challenge 1.

## Submission

Commit `raw-notes.md` (and the `pr-482.diff`-applied `app.py`, left applied — you'll need it for Exercise 2) to your portfolio under `c50-week-11/exercise-01/`.
