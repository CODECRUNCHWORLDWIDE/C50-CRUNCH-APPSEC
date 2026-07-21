# Exercise 2 — Find a Security Misconfiguration

**Goal:** Independently trigger and evidence both A05 misconfigurations in `crunch-notes` — the exposed debug console and the missing security headers — fix both, and re-test.

**Estimated time:** 90 minutes.

## Before you start

Make sure you're running the **unfixed** version of `app.py` for Tasks 1–3 (still `debug=True`, no `after_request` header hook). If you've already applied Lecture 3's fix while reading along, temporarily revert it so you can capture real "before" evidence — a fix you can't reproduce failing isn't proven.

## Task 1 — Trigger the debug leak

`/notes/<note_id>` never validates that `note_id` is actually a number before using it. Find a request that breaks it.

```bash
curl -s -b alice.txt "http://127.0.0.1:5000/notes/not-a-number" -o debug-response.html
```

Open `debug-response.html` in a browser (not just `curl` — the Werkzeug debugger is a full interactive page). Answer, in `evidence-misconfig.md`:

1. What HTTP status code came back?
2. What can you see in the response that a well-behaved production error page should never show? Name at least three specific things (e.g., file path, line number, a local variable's value, the raw source line that failed).
3. If this were a real production deployment, what's the worst thing an attacker could do once they've found this page? (Hint: re-read Lecture 3, Section 1 about the interactive console.)

## Task 2 — Audit the response headers

```bash
curl -s -I http://127.0.0.1:5000/notes -b alice.txt > headers-before.txt
cat headers-before.txt
```

In `evidence-misconfig.md`, list which of these three headers are present and which are missing:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`

For each **missing** header, write one sentence on what kind of attack it would have made harder if it were present (Lecture 3, Section 1 names what each one stops).

## Task 3 — Score the finding

Score the misconfiguration as a whole using risk = likelihood × impact. Consider: how easy is it to *find* (a single malformed request, no special tooling) versus how bad it is if found (source disclosure, potentially remote code execution via the debugger console). Justify both numbers in `evidence-misconfig.md`.

## Task 4 — Fix both, at the source

Apply Lecture 3, Section 1's fix to your own `app.py`:

1. Add the `@app.after_request` hook setting all three headers.
2. Make `debug` default to `False`, gated behind an explicit environment variable you set yourself for local development only.

Restart the app with debug **off** (don't set `CRUNCH_NOTES_DEBUG`):

```bash
python3 app.py
```

## Task 5 — Re-test

```bash
# the same malformed request must now return a generic error, not the debugger
curl -s -o debug-response-after.html -w "%{http_code}\n" "http://127.0.0.1:5000/notes/not-a-number" -b alice.txt

# headers must now all be present
curl -s -I http://127.0.0.1:5000/notes -b alice.txt > headers-after.txt
diff headers-before.txt headers-after.txt
```

Confirm `debug-response-after.html` no longer contains source code, file paths, or a console — just a plain error. Confirm `headers-after.txt` includes all three headers `headers-before.txt` was missing.

## Expected result (spot checks)

- `debug-response.html` (before) visibly contains a stack trace with file paths and local variables; `debug-response-after.html` does not.
- `headers-before.txt` is missing at least `X-Content-Type-Options` and `X-Frame-Options`; `headers-after.txt` has all three.
- `evidence-misconfig.md` states a risk score with justification, and answers all three Task 1 questions.

## Done when…

- [ ] `evidence-misconfig.md` documents the debug leak, the missing headers, and the risk score.
- [ ] Your `app.py` sets all three security headers and defaults `debug` to off.
- [ ] Both before/after response files exist and clearly differ in the expected way.
- [ ] You can explain, in one sentence, why toggling `debug` with an environment variable (rather than editing the source every time) matters for a real deployment.

## Stretch

- `crunch-notes` also ships over plain HTTP with no `Strict-Transport-Security` header — appropriate for this `127.0.0.1` lab, but explain in `evidence-misconfig.md` what that header does and why you'd add it (and switch `SESSION_COOKIE_SECURE` to `True`, from Lecture 3, Section 3) the moment this app is deployed behind real HTTPS.

## Submission

Commit `evidence-misconfig.md`, `debug-response.html`, `debug-response-after.html`, `headers-before.txt`, `headers-after.txt`, and your updated `app.py` to your portfolio under `c50-week-03/exercise-02/`. Exercise 3 loads this finding into a database alongside Exercise 1's two.
