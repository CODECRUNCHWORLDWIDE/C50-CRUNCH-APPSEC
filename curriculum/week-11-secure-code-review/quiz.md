# Week 11 — Quiz

Fourteen questions. Lectures closed. Aim for 12/14 before starting the mini-project. A mix of multiple-choice and short "what's the flaw" questions — the answer key at the bottom explains the *why*, not just the letter.

---

**Q1.** What is the correct order of this week's four-step review method?

- A) Verify controls → catalog sinks → map entry points → taint-trace
- B) Map entry points → catalog sinks → taint-trace → verify controls
- C) Taint-trace → map entry points → verify controls → catalog sinks
- D) There is no fixed order — read the code and see what stands out

---

**Q2.** Why does Lecture 1 insist on building the entry-point table by grepping the routing decorator (`grep -n "@app.route"`) instead of working from the PR description's list of "what this adds"?

- A) Grep is faster to type than reading English
- B) A PR description can omit or mischaracterize a route; a mechanical inventory doesn't depend on what the author chose to mention
- C) PR descriptions are not valid Markdown
- D) It isn't necessary — the description is authoritative

---

**Q3.** In `crunch-invoices`'s `PR #482`, which of the following is correctly classified as a **sink**, per Lecture 1's catalog?

- A) `request.args.get("q")`
- B) The `session["role"]` check that *should* run in `export_invoices` but doesn't
- C) A route's URL path
- D) The `require_login()` helper function's name

---

**Q4.** In the SQL injection trace (Lecture 2, Section 2), at which hop does the vulnerability actually occur?

- A) At `get_db().execute(sql)` — the final call is always where the vulnerability "happens"
- B) At `request.args.get("q", "")` — the source itself is the vulnerability
- C) Inside `build_search_query`, where `term` is spliced into `clause` via an f-string
- D) There is no single hop — SQL injection has no specific location

---

**Q5.** Why does converting `invoice_id` with `int(invoice_id)` fail as a control for an *authorization* question, even though it's a reasonable defense against certain injection payloads?

- A) `int()` always throws an exception, so it's never actually applied
- B) Type conversion says nothing about whether the *caller* is allowed to access the object that ID refers to
- C) `int()` is itself a SQL sanitizer, so no further check is needed
- D) Authorization checks must always come before type conversion, never after

---

**Q6.** `crunch-invoices`'s `export_invoices` route checks `if "user_id" not in session`. What control question does this satisfy, and what does it leave unanswered?

- A) Satisfies authorization fully; nothing left unanswered
- B) Satisfies authentication only; leaves the role check and the account/tenant filter unanswered
- C) Satisfies injection defense; leaves authentication unanswered
- D) Satisfies nothing — the check is syntactically invalid

---

**Q7.** Why are the hardcoded `SIGNING_KEY`, the `hashlib.md5`-based signature, and the `sig == expected` comparison written up as **three separate findings** rather than one?

- A) More findings always look more thorough in a report
- B) They share one root cause, so combining them is actually more correct
- C) Each has an independent fix, and fixing only one of the three leaves the other two vulnerabilities in place
- D) Lecture 3's template requires a minimum of three findings per route

---

**Q8.** Using Lecture 3's severity rubric, a flaw that lets **any authenticated user** (regardless of role) read invoices belonging to a **different tenant account** lands in which cell?

- A) Critical — because cross-tenant reach is always Critical regardless of who can trigger it
- B) High — authenticated-only reach, crossed with cross-tenant data read
- C) Low — because the attacker needed to log in at all
- D) Medium — because it doesn't involve a write

---

**Q9.** What's specifically wrong with the finding "Search feature might be vulnerable to injection, should probably fix," per Lecture 3?

- A) Nothing — it correctly identifies the vulnerability class
- B) It's too long
- C) It has no location, no reproduction, no impact, and no concrete fix — a developer can't act on it without redoing the investigation themselves
- D) It should have been reported verbally instead of in writing

---

**Q10.** Why does a finding require a **reproduction** — a real command and real output — before it's written up, rather than being reported as soon as you suspect something while reading the code?

- A) Reproductions are optional; they just make the report longer
- B) Without confirmation, a suspicion can turn out to be a false alarm, and false alarms burn the trust every other finding in the same report needs
- C) Only reproductions written in Python count as valid evidence
- D) Reproductions are required only for `critical` severity findings

---

**Q11.** In the `review_findings` schema, which column tracks whether a finding has been confirmed fixed **and** re-verified against the original reproduction, as opposed to merely having a code change made?

- A) `status = 'fixed'`
- B) `status = 'retested_ok'`
- C) `resolved_at IS NOT NULL`
- D) `severity = 'low'`

---

**Q12.** A SAST scanner (Week 8) is run against `crunch-invoices` alongside a manual review. Which of the following is the scanner **most likely to miss**, and why?

- A) The SQL injection in `build_search_query` — scanners are generally weak at recognizing string concatenation into a query
- B) The hardcoded `SIGNING_KEY` — scanners are generally weak at recognizing literal secret-shaped strings in source
- C) The missing role/account check in `export_invoices` — the flaw requires knowing this app's *intended* authorization model, which is a semantic fact a generic ruleset has no way to encode
- D) The use of `hashlib.md5` — scanners are generally weak at recognizing calls to known-weak cryptographic functions

---

**Q13.** Why does Challenge 1 explicitly ask you to re-verify the *already-reviewed* `main`-branch routes, not just `PR #482`'s new ones?

- A) Old code is statistically more likely to contain bugs than new code
- B) A review that only checks new code and silently assumes old code is fine isn't a full review — and "verified clean" needs the same evidence standard as a real finding
- C) The `main` branch is untested and therefore riskier by definition
- D) It isn't necessary — Exercise 1 already covered everything relevant

---

**Q14.** `re.sub(r"[^a-zA-Z0-9]", "", user_input)` is applied before splicing a value into a shell command. Is this a real sanitizer, and what's the honest caveat?

- A) Yes, fully — no shell metacharacter can survive this filter
- B) Yes for shell metacharacters specifically, but it also breaks any legitimate input containing spaces, punctuation, or non-ASCII characters — restrictive, not precise
- C) No — regular expressions cannot be used for input validation under any circumstance
- D) It's irrelevant, since shell commands can't be injected via string input

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — map entry points, then catalog sinks, then taint-trace between them, then verify the specific controls. Each step depends on the inventory the previous step built.
2. **B** — a PR description is written by the author and can omit or soften what a change actually does; a mechanical grep-based inventory finds every route regardless of what got mentioned.
3. **B** — a missing authorization decision point is explicitly named as its own sink category in Lecture 1, because untrusted *access* (not just untrusted *data*) reaching it unchecked is the danger. A's, C's, and D's items are entry points or plumbing, not sinks.
4. **C** — the f-string `f"customer_name LIKE '%{term}%'"` inside `build_search_query` is where the untrusted value is first spliced into something interpreted as SQL syntax rather than treated as data. The final `execute()` call is the sink where the damage is realized, but the vulnerability — the missing parameterization — happens at the splice.
5. **B** — authorization asks "is *this caller* allowed to touch *this object*," a question about identity and ownership that a type conversion has no information about at all.
6. **B** — `"user_id" not in session` proves only that some valid session exists (authentication). It never reads `session["role"]` or `session["account_id"]`, so it answers nothing about authorization.
7. **C** — the hardcoded key, the weak MD5-concatenation construction, and the non-constant-time compare each have an independent, different fix. Fixing the comparison to `hmac.compare_digest` while the key stays hardcoded still leaves the key exposed via source or git history; fixing the key's storage while still using MD5-concatenation still leaves a broken MAC construction.
8. **B** — High. Per the rubric, "any authenticated user" reach crossed with "reads/leaks data across tenants" lands in the High cell; Critical in that row is reserved for unauthenticated reach.
9. **C** — it names a vulnerability class but gives no specific location, no proof it's real, no stated impact, and no concrete fix — a developer reading it has to redo the entire investigation before they can act.
10. **B** — an unconfirmed suspicion can be wrong, and reporting a false alarm alongside real findings damages the credibility of the whole report, including the findings that are correct.
11. **B** — `status = 'retested_ok'` specifically means the original reproduction was re-run against the fixed code and confirmed no longer to succeed; `'fixed'` alone only means a code change was made, not that it was verified.
12. **C** — the injection (A), the hardcoded secret (B), and the weak hash function (D) are all syntactic patterns a generic ruleset can be written to match. Whether `export_invoices` checks "enough" authorization requires knowing this specific app's intended model (which roles should reach which routes, filtered by which column) — a semantic fact no generic rule has access to.
13. **B** — a review that produces findings only for new code and treats old code as exempt from scrutiny isn't a full review; "verified clean" is itself a claim that needs evidence (a quoted line, a confirming request), the same standard a real finding is held to.
14. **B** — the filter does strip characters commonly used for shell metacharacter injection, but it's an overly blunt instrument: it also destroys any legitimate input with spaces, hyphens, apostrophes, or non-ASCII text, which is a correctness problem even where it happens to also be "safe." The right fix for shell commands is avoiding `shell=True` and passing arguments as a list, not filtering characters out of a string that will still be interpreted by a shell.

</details>

**Scoring:** 12+ → start the mini-project. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; this week's method only works if every step is automatic before the mini-project asks you to run all four on a whole app.
