# Week 12 — Quiz

Fifteen questions. Lectures closed. This is the final quiz of **C50 · Crunch AppSec** — aim for 13/15 before you consider the course complete. A mix of multiple-choice and short reasoning questions — the answer key explains the *why*, not just the letter.

---

**Q1.** Why does Lecture 1 insist on a written scope and authorization statement even when the target is an app you wrote yourself, with no other users?

- A) It's a formality with no real function once you own the app outright.
- B) The discipline of writing scope down, every week, is what a reviewer or a real team will actually ask for first — skipping it because "it's obviously fine" is the exact habit this course has argued against since Week 1.
- C) Only apps with multiple users legally require a scope document.
- D) It's required only if the app will eventually be deployed publicly.

---

**Q2.** In a data-flow diagram, what specifically is a "trust boundary," and why did Lecture 1 identify two of them for Crunch Ledger?

- A) The physical network cable connecting two servers.
- B) A point where privilege or trust level changes — such as the network edge (unauthenticated → authenticated) and the data-store boundary (every process reads/writes shared data unless a query restricts it) — and STRIDE threats concentrate exactly at these points.
- C) A boundary is any line drawn on the diagram for visual clarity; it has no security meaning.
- D) A trust boundary only exists between two different companies' systems, never within one app.

---

**Q3.** Lecture 1's STRIDE table included two rows — a missing audit log and an unbounded search query — that don't correspond to any of Crunch Ledger's eleven numbered vulnerabilities. What does this demonstrate?

- A) The eleven numbered vulnerabilities were incomplete and should be renumbered to thirteen.
- B) Threat modeling can surface design gaps (an audit log that was never built) that no code scanner could ever find, since there's no "vulnerable line" for a control that doesn't exist at all.
- C) STRIDE only applies to vulnerabilities a scanner has already found.
- D) Repudiation and Denial of Service are not real STRIDE categories.

---

**Q4.** Why is `status = 'accepted'` a legitimate value in the risk register, rather than something to avoid entirely?

- A) It isn't legitimate — every risk-register row must eventually reach `mitigated`.
- B) Not every risk can or should be fixed in a given release; a register with a clearly-justified accepted risk (likelihood, impact, and reasoning written down) demonstrates judgment, while a register claiming a perfect zero is often dishonest or unexamined.
- C) `accepted` is only valid for `low`/`low` likelihood-impact rows.
- D) Risk registers should never include a status field at all.

---

**Q5.** VULN #4 (IDOR on `/expenses/<id>`) is fixed by moving the ownership check into the SQL `WHERE` clause rather than an `if` statement after the fetch. Why is the query-level fix more durable?

- A) SQL `WHERE` clauses execute faster than Python `if` statements, which is the only reason to prefer one.
- B) A follow-up `if` check can be silently skipped by a new early-return code path added later; embedding the check in the query means the authorization decision and the data lookup are the same operation, so there's no separate branch to forget.
- C) SQLite doesn't support `if` statements, so this isn't actually a choice.
- D) The two approaches are equivalent; either is acceptable.

---

**Q6.** VULN #7's fix replaces `random.randint()` with `secrets.token_urlsafe()` for a password-reset token. What's the precise reason `random` is wrong here?

- A) `random` produces strings that are too short.
- B) `random`'s output (Mersenne Twister) is deterministic given its seed and is not cryptographically secure, making it unsuitable for any value — key, token, or nonce — that must be unpredictable to an attacker; `secrets` draws from a CSPRNG instead.
- C) `random` cannot generate alphanumeric strings.
- D) `random` and `secrets` are functionally identical in Python 3.10+.

---

**Q7.** Why does `hmac.compare_digest` close VULN #8, when the original `==` comparison seemed to work correctly in every functional test?

- A) `==` produces incorrect results for equal strings; it was a functional bug all along.
- B) `==` returns as soon as it finds a mismatched byte, so response timing can leak how many leading bytes of a guessed signature were correct — a functional test never exercises timing, only correctness, so the flaw is invisible to normal testing.
- C) `hmac.compare_digest` is simply a faster version of `==` with no security difference.
- D) The fix is unnecessary because HMAC signatures cannot be forged regardless of comparison method.

---

**Q8.** Lecture 2's CI/CD fix (VULN #11) makes two specific changes to `ci_pipeline.yml`. What are they, and why does fixing only one leave a real gap?

- A) Renaming the job and adding a comment — cosmetic changes only.
- B) Removing `|| true` so test failures actually block the pipeline, and adding blocking SAST/SCA steps gated before deploy; fixing only the first still lets a passing-but-vulnerable build (a Bandit or `pip-audit` finding) reach "prod," and fixing only the second still lets a failing test ship if the failure itself doesn't stop the job.
- C) Switching from YAML to JSON and adding more comments.
- D) Adding a Slack notification and increasing the timeout value.

---

**Q9.** Lecture 3 re-runs SAST, DAST, and SCA against code that was already manually fixed and manually re-tested in Lecture 2. Why is this not redundant?

- A) It is redundant; Lecture 2's manual re-tests are sufficient on their own.
- B) A belief that a fix works and a proof that it works are different claims, and independent tooling (plus a fresh manual review) can surface issues the original build's mental model — anchored to the eleven known bugs — never considered.
- C) Automated tools always contradict manual findings, so both must be run to see which one is "right."
- D) SAST, DAST, and SCA are three names for the same technique, so running all three is only for redundancy in case one tool crashes.

---

**Q10.** The manual review in Lecture 3 finds that a manager can approve their own expense — a bug none of the eleven numbered vulnerabilities describe and no scanner flagged. What category of issue is this, and why couldn't SAST/DAST/SCA tooling find it?

- A) A SQL injection vulnerability that the tools simply missed by chance.
- B) A business-logic flaw — the role check technically passed (a manager IS allowed to approve expenses), but the design never modeled the relationship between approver and submitter; tools check for known patterns and CWEs, not whether a policy makes business sense.
- C) A dependency vulnerability that `pip-audit` should have caught but didn't.
- D) A session-cookie configuration issue.

---

**Q11.** In the findings-triage query, why does severity take priority over source (SAST vs. DAST vs. manual) when ordering the backlog?

- A) Source never matters at all and should be removed from the schema entirely.
- B) The backlog's purpose is to fix what matters most first; a critical manual-review finding is more urgent than a low-severity SAST finding, regardless of which tool or process surfaced it — the finding's real-world impact drives order, not its origin.
- C) SAST findings are always more severe than DAST findings by definition.
- D) Triage order should always match the order findings were discovered, chronologically.

---

**Q12.** What does Challenge 1 require for a finding to move from `open` to `wont_fix`, rather than simply marking it closed?

- A) Nothing — any finding can be marked `wont_fix` at the assessor's discretion with no further requirement.
- B) A written answer to all four of Lecture 3 Section 8's questions: what's the risk, its likelihood/impact and why rated that way, any compensating control, and what would have to change for the decision to need revisiting.
- C) Manager approval via a Slack message, screenshotted into the notes field.
- D) A `wont_fix` status is not permitted anywhere in this course's data model.

---

**Q13.** Why does the mini-project's rubric explicitly penalize a capstone that ships with "everything fixed, nothing accepted, zero residual risk" as a red flag rather than a strength?

- A) It doesn't — a perfect zero is always the strongest possible outcome.
- B) Real shipped software almost always carries some accepted risk, explicit or not; a claim of zero residual risk usually means the risk wasn't examined carefully enough to find it, not that none exists — the professional move is finding, sizing, and owning at least one real trade-off, not claiming perfection.
- C) Residual risk is only relevant for applications with regulatory compliance requirements.
- D) The rubric doesn't consider residual risk at all; it only scores fixed vulnerability count.

---

**Q14.** Challenge 2's design-defense review asks, "If I changed one thing about your threat model — say, added a second company sharing this app — which of your current fixes would break?" What is this question actually testing?

- A) Whether you memorized the exact wording of every fix.
- B) Whether your fixes generalize to the actual threat model's assumptions, or whether they were narrowly shaped to pass the specific test cases you happened to run — the same distinction Week 6 drew between a fix that closes a vulnerability class versus one that only blocks the one exploit you tried.
- C) Whether Crunch Ledger technically supports multi-tenancy today.
- D) Whether you can rewrite the entire app from scratch during the review.

---

**Q15.** What is the single throughline connecting every week of C50, made explicit in this capstone's mini-project rubric?

- A) Every vulnerability class has exactly one correct fix, applied identically regardless of context.
- B) Security is proven, not claimed: a threat model that reasons about design, a fix that closes a whole class of bug at its source, and a finding that's marked resolved only after a logged, repeatable re-test — evidence over assertion, every single week, culminating in one application you can defend under real questioning.
- C) Scanners are sufficient on their own once a CI pipeline is correctly configured.
- D) The goal of application security is finding the maximum possible number of vulnerabilities, regardless of severity or fix quality.

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — the habit of writing scope down every single week, regardless of how obvious "of course it's my own app" feels, is the discipline this course has insisted on since Week 1; skipping it "because it's obviously fine" is precisely the shortcut the course argues against.
2. **B** — a trust boundary is where privilege or trust level changes (unauthenticated→authenticated at the network edge; shared-access at the data-store boundary), and STRIDE threats cluster at exactly these transition points, which is why Crunch Ledger's DFD names two of them explicitly.
3. **B** — threat modeling reasons about the design itself, so it can surface a control that was never built (an audit log) — a scanner can only flag a vulnerable *line*, and a missing feature has no line to flag.
4. **B** — a defensible `accepted` status, backed by written likelihood/impact/reasoning, reflects real judgment about limited time and real trade-offs; a register claiming zero accepted risk is often a sign the risk wasn't looked for hard enough, not that none exists.
5. **B** — embedding the check in the `WHERE` clause makes the authorization decision inseparable from the data lookup, so there's no separate code path a future refactor or early-return could accidentally bypass, unlike a follow-up `if`.
6. **B** — `random`'s Mersenne Twister output is deterministic given its seed and not cryptographically secure; any value that must be unguessable by an attacker (keys, tokens, nonces) needs a CSPRNG-backed source like `secrets`.
7. **B** — `==` short-circuits on the first mismatched byte, which functional tests (checking only "does it return true/false correctly") never observe, but which a patient attacker measuring response timing can exploit to recover a valid signature byte by byte.
8. **B** — removing `|| true` makes test failures actually block, and adding blocking SAST/SCA steps gated before the deploy job closes the "no gate at all" half separately; fixing only one leaves the other half's exact failure mode (a vulnerable-but-passing build, or a failing-but-shipped build) fully open.
9. **B** — believing a fix works and proving it works are different claims; independent tools and a fresh manual review aren't anchored to the same mental model as the original fix and can catch what that model missed.
10. **B** — it's a business-logic flaw: every individual check (role, session) technically passed, but the design never modeled the approver/submitter relationship — a gap tools can't find because it isn't a known vulnerability pattern, it's a missing piece of policy.
11. **B** — the backlog exists to drive what gets fixed first, and real-world impact (severity) is what should drive that decision, regardless of which process or tool happened to surface the finding.
12. **B** — Lecture 3 Section 8's four questions (the risk, its likelihood/impact and reasoning, any compensating control, and the revisit condition) must all be answered in writing before a finding can legitimately move to `wont_fix` rather than simply being marked closed without justification.
13. **B** — real software almost always carries some accepted risk; a claimed perfect zero more often signals an under-examined risk assessment than a genuinely risk-free release, so the rubric rewards a specific, owned trade-off over an unexamined "everything's fine."
14. **B** — the question probes whether a fix generalizes to the model's actual assumptions or was narrowly shaped to pass only the specific test cases already run — the same "class of bug vs. one exploit" distinction Week 6 drew for access-control fixes specifically.
15. **B** — every week of this course has built toward proving security claims with evidence rather than asserting them, and the capstone's mini-project rubric makes that throughline explicit: reasoned threat models, source-level fixes, and logged re-tests, all defensible under real questioning.

</details>

**Scoring:** 13+ → you've completed **C50 · Crunch AppSec**. 10–12 → re-read the lecture sections behind your misses before calling the course finished. <10 → re-read all three lectures from the top; this capstone is meant to prove the whole course held together, and a shaky quiz score here usually means an earlier week's habit didn't fully stick.
