# Week 8 — Quiz

Fifteen questions. Lectures closed. Aim for 13/15 before starting Week 9. A mix of multiple-choice and short reasoning questions — the answer key explains the *why*, not just the letter.

---

**Q1.** What is the fundamental difference in vantage point between SAST and DAST?

- A) SAST is for web apps, DAST is for mobile apps.
- B) SAST reads source code without running the program; DAST sends real requests to a running application without seeing its source.
- C) SAST is always more accurate than DAST.
- D) There is no real difference; they're marketing terms for the same technique.

---

**Q2.** In a SAST taint-tracking model, what are the three elements a source-to-sink flow requires to be flagged as dangerous?

- A) A source, a sink, and no sanitizer breaking the path between them.
- B) A source, a database, and a network connection.
- C) A vulnerability, a CVE ID, and a patch.
- D) A rule, a severity, and a CWE tag — nothing about data flow matters.

---

**Q3.** Why is a missing authorization check (an IDOR) notoriously difficult for SAST tools to catch reliably?

- A) SAST tools can't parse authorization-related code at all.
- B) The code that reads a resource by ID is often syntactically fine — the bug is the *absence* of an ownership check that was never written, and there's no dangerous "shape" to pattern-match against an absence.
- C) IDOR vulnerabilities don't involve any code, only network configuration.
- D) SAST tools are specifically disabled from checking authorization by their vendors.

---

**Q4.** What does a Semgrep rule's `pattern-not` clause accomplish in the rule from Lecture 1, Section 5?

- A) It excludes the safe shape (a parameterized call with a bound-parameters argument) from matching, so the rule only fires on the dangerous concatenation shape.
- B) It disables the rule entirely.
- C) It has no effect; it's optional decoration.
- D) It only works in Python, not JavaScript.

---

**Q5.** Why is a scanner's own severity rating (e.g., Semgrep's `ERROR`) not the same thing as your triaged risk score?

- A) They're identical; there's no meaningful distinction.
- B) The scanner's severity reflects the rule author's general judgment about the pattern; your risk score (`likelihood × impact`) reflects the specific context of your actual app, which can meaningfully differ.
- C) Risk scores only apply to DAST findings, not SAST.
- D) Scanner severity is always higher than a properly computed risk score.

---

**Q6.** In OWASP ZAP's architecture, which stage sends zero additional requests beyond what discovery already generated?

- A) The spider.
- B) The passive scan — it analyzes traffic already seen, without sending anything new.
- C) The active scan.
- D) All three stages send additional requests equally.

---

**Q7.** Why does an authenticated ZAP scan typically surface substantially more findings than an anonymous baseline scan?

- A) Authenticated scans use a different, more aggressive payload set unrelated to reachability.
- B) Most of a real application's attack surface — checkout, profile editing, order history — sits behind a login, and an anonymous crawler simply cannot reach it at all.
- C) Anonymous scans are technically incapable of finding any real vulnerabilities.
- D) There's no real difference; the finding-count gap is a reporting artifact.

---

**Q8.** ZAP rates every alert on two independent axes. What are they, and what does a "High risk / Low confidence" alert mean?

- A) Speed and cost; it means the scan ran quickly but was expensive.
- B) Risk (how bad if real) and Confidence (how sure the tool is this specific instance is real); a High-risk/Low-confidence alert could be a serious finding hiding behind an uncertain detection, and deserves manual verification rather than being dismissed for its low confidence.
- C) Only "Risk" exists; "Confidence" is not a real ZAP concept.
- D) Confidence measures how confident the target application is in its own security.

---

**Q9.** A ZAP scan flags a missing `X-Frame-Options` header on a pure JSON API endpoint that's never rendered directly in a browser frame. What's the correct way to think about this alert?

- A) It's automatically a critical, must-fix finding regardless of context.
- B) It's a real but often low-priority finding in this specific context — the header exists to prevent browsers from dangerously rendering HTML content, which doesn't apply the same way to an endpoint that only ever returns JSON and is never framed.
- C) Missing headers are never worth investigating under any circumstances.
- D) This proves ZAP's passive scanner is fundamentally broken.

---

**Q10.** What question does SCA answer that neither SAST nor DAST directly answers?

- A) "Is this specific function call syntactically dangerous?"
- B) "Does the running application leak information over HTTP?"
- C) "Do any of the specific third-party library versions I depend on have a publicly disclosed, known vulnerability?"
- D) SCA answers the exact same question as SAST, just for a different language.

---

**Q11.** What is the "reachability problem" in SCA, and why does it matter for triage?

- A) It refers to whether the scanner itself can reach the internet to update its database.
- B) A dependency scan can correctly match a real CVE to an installed library version while the vulnerable function is never actually called anywhere in your application's code path — the CVE match is real, but the practical risk in your specific app may be far lower than the raw CVSS score suggests.
- C) It means SCA tools cannot reach any dependency more than one level deep.
- D) Reachability is a DAST-only concept; it doesn't apply to SCA at all.

---

**Q12.** Three different scanners could describe the *same* underlying weakness (e.g., a hardcoded JWT secret) in three different ways, or one tool might catch it while the others stay silent. What is the correct response to this, per Lecture 3?

- A) Ignore the discrepancy; scanner disagreement is meaningless noise.
- B) Always trust whichever scanner has the scariest-sounding message.
- C) Recognize that reconciliation — grouping findings that share a genuine root cause while correctly keeping distinct findings separate — is a deliberate, evidence-based step, not something to skip or do carelessly.
- D) Automatically merge any two findings that mention the same keyword, regardless of root cause.

---

**Q13.** What does a properly disciplined findings backlog require before a finding's `status` can be set to `false_positive`?

- A) Nothing — any finding can be dismissed without explanation.
- B) A written, specific justification (`triage_notes`) explaining exactly why the finding doesn't represent a real risk — e.g., "sanitized via the framework's built-in escaping, confirmed by reading the code," not "doesn't look like a big deal."
- C) A false positive can only be declared by the tool vendor, never by the team using the tool.
- D) `false_positive` status requires deleting the row from the database entirely.

---

**Q14.** Why does this week's `findings` schema keep both a `severity_raw` and a `severity_normal` column instead of just normalizing and discarding the tool's original rating?

- A) Storing both wastes space with no real benefit.
- B) `severity_raw` preserves an audit trail back to exactly what the original tool reported (useful if the normalization mapping is questioned or refined later), while `severity_normal` lets you rank findings from different tools on one consistent scale — both serve different, real purposes.
- C) SQLite requires at least two severity columns by design.
- D) `severity_normal` is only used for DAST findings; SAST and SCA findings only need `severity_raw`.

---

**Q15.** A team says: "our SAST scan came back clean, so this endpoint is secure." What is the most accurate response, drawing on this week's material?

- A) Agree completely — a clean SAST scan is sufficient proof of security.
- B) A clean SAST scan means no known-dangerous code *shapes* were detected in the source; it says nothing about missing-authorization logic flaws, runtime misconfiguration, or vulnerabilities in third-party dependencies — all of which require DAST, SCA, and manual review respectively to have any chance of catching.
- C) SAST tools are incapable of ever returning a clean result, so this claim must be false.
- D) A clean SAST result is only meaningful for compiled languages, never for JavaScript.

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — SAST never executes the program and reads only source; DAST sends real HTTP traffic to a live, running target and never looks at source at all.
2. **A** — a dangerous taint flow requires an untrusted source, a dangerous sink, and no recognized sanitizer breaking the path between them; missing any one of the three means the engine won't (and shouldn't) flag it as that specific flow.
3. **B** — the code reading a resource by ID is often syntactically ordinary; the vulnerability is the *absence* of an authorization check that was never written, and static pattern-matching has no dangerous shape to match against something that isn't there.
4. **A** — `pattern-not` explicitly excludes the safe shape (a parameterized call with a second, bound-parameters argument) so the rule only fires on the dangerous concatenation pattern, not on code that's already using the fix.
5. **B** — scanner severity reflects the rule author's general judgment about a pattern; your risk score reflects likelihood and impact specific to your actual app and context, which can genuinely diverge from the tool's generic rating.
6. **B** — the passive scan analyzes traffic already generated by the spider, with zero additional requests sent; only the active scan sends new, crafted payloads.
7. **B** — most of a real app's attack surface (checkout, profile, order history) sits behind login; an anonymous crawler structurally cannot reach any of it, so authenticated scans discover far more.
8. **B** — Risk (how bad if real) and Confidence (how sure the tool is this instance is real) are independent axes; a High-risk/Low-confidence alert deserves manual verification precisely because it might be a serious finding the tool is only partially sure about.
9. **B** — the header exists to stop browsers from dangerously rendering HTML in a risky context; a pure JSON API endpoint never framed by a browser has a real but low-priority version of this finding, and understanding why matters more than the raw "missing header" fact alone.
10. **C** — SCA answers whether specific installed library versions have a publicly disclosed, known vulnerability — a lookup against vulnerability databases, not a code-shape or live-traffic question.
11. **B** — a real CVE match against an installed library version can exist alongside the vulnerable function never actually being called in your app's code path, meaning the practical risk may be much lower than the CVE's raw severity implies.
12. **C** — reconciliation is a deliberate, evidence-based process: merge findings with a genuinely shared root cause, and explicitly document why distinct-but-similar-looking findings are kept separate; neither ignoring disagreement nor blindly merging by keyword is correct.
13. **B** — a false positive requires a specific written justification tied to actual evidence (e.g., confirmed sanitization) — a vague dismissal fails this course's triage discipline.
14. **B** — `severity_raw` preserves the original tool's rating as an audit trail; `severity_normal` enables consistent cross-tool ranking; both serve distinct, legitimate purposes and neither should be discarded.
15. **B** — a clean SAST result only means no known-dangerous code shapes were found in source; it says nothing about missing-authorization logic flaws (DAST/manual review territory), runtime misconfiguration, or vulnerable dependencies (SCA territory) — the exact reasoning Homework Problem 4 has you practice explaining to a skeptical engineer.

</details>

**Scoring:** 13+ → start Week 9. 10–12 → re-read the lecture sections behind your misses. <10 → re-read all three lectures from the top; the SAST/DAST/SCA blind-spot distinctions and the triage discipline compound every week from here.
