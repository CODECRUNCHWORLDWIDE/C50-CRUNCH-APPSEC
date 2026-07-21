# Week 1 — Quiz

Fifteen questions. Lectures closed. Aim for 13/15 before starting Week 2. A mix of multiple-choice and short reasoning questions — the answer key explains the *why*, not just the letter.

---

**Q1.** Which statement correctly distinguishes a **threat** from a **vulnerability**?

- A) They're synonyms; either word works.
- B) A threat is a potential cause of harm; a vulnerability is the weakness that could be exploited to cause it.
- C) A vulnerability is always caused by a threat.
- D) A threat only exists after a vulnerability has already been exploited.

---

**Q2.** A hardcoded database password is found in a public GitHub repository belonging to a live, internet-facing production application. What is the most defensible **likelihood** score (1–5)?

- A) 1 — very unlikely, requires physical access
- B) 2 — unlikely, requires a sophisticated targeted attack
- C) 4 or 5 — easily discoverable and trivially usable by anyone who finds the repo, including automated scanners that search public code for exactly this pattern
- D) Likelihood doesn't apply to credential exposure

---

**Q3.** `Risk = Likelihood × Impact`. A finding scores Likelihood 2, Impact 5. What risk band does it fall in?

- A) Low (1–4)
- B) Medium (5–9)
- C) High (10–15)
- D) Critical (16–25)

---

**Q4.** An attacker modifies another user's order total by tampering with a request parameter, without needing to read anything else. Which CIA property is **primarily** violated?

- A) Confidentiality
- B) Integrity
- C) Availability
- D) None of the three — this isn't a security issue

---

**Q5.** Why is "a threat without a vulnerability" **not** a risk?

- A) Threats don't count unless they're financially motivated.
- B) Without an exploitable weakness for the threat to act through, there's nothing for the threat to actually succeed against.
- C) Risk only requires a threat, never a vulnerability.
- D) This statement is false — a threat alone is always a risk.

---

**Q6.** Which of the following is the **best** description of "attack surface"?

- A) The number of security bugs a system currently has.
- B) The complete set of points where an untrusted actor could interact with the system.
- C) Only the endpoints listed in the public API documentation.
- D) The total lines of code in the application.

---

**Q7.** In the Lecture 1 breach walkthrough, what was the **root** structural failure that let an internal-only endpoint become internet-reachable?

- A) A zero-day vulnerability in the web framework.
- B) A network trust boundary that was assumed ("internal only") but never actually enforced in infrastructure or code.
- C) The developer used a weak password.
- D) The database was left completely unencrypted.

---

**Q8.** Why does this course require findings, risk scores, and telemetry to be stored in SQL (or via Python), and explicitly **never** in a spreadsheet?

- A) Spreadsheets can't store text, only numbers.
- B) Spreadsheets have no enforced schema or constraints, invite untracked silent edits, and don't give you real, repeatable queries the way a `findings` table does.
- C) SQL is required by law for security work.
- D) There's no real difference; it's a stylistic preference only.

---

**Q9.** Which Docker command correctly publishes a lab target so it's reachable **only** from your own machine, not from anywhere else on your network?

- A) `docker run -d -p 3000:3000 juice-shop`
- B) `docker run -d -p 0.0.0.0:3000:3000 juice-shop`
- C) `docker run -d -p 127.0.0.1:3000:3000 juice-shop`
- D) All three are equally safe.

---

**Q10.** You've built what you believe is an isolated lab. What is the **correct** next step before running any exercise against it?

- A) Trust the setup — if you followed the steps, it's isolated.
- B) Actively verify isolation from a second device on your network, confirming the lab is unreachable from outside your host.
- C) Skip verification; it only matters for network-level (VM) labs, not Docker-based web-app labs.
- D) Ask a friend on a different network to try connecting, since that's the only valid test.

---

**Q11.** Why does this course require **written authorization**, **defined scope**, and **verified isolation** as three separate controls, rather than treating any one of them as sufficient alone?

- A) It's redundant bureaucracy; any one of the three would be enough.
- B) Each covers a distinct failure mode the others don't — authorization alone doesn't prevent a technical mistake from reaching an unintended system, isolation alone doesn't teach the process real engagements require, and scope alone means nothing without someone actually agreeing to it.
- C) The law only requires isolation; the other two are optional best practice.
- D) Scope and authorization are the same document by definition, so this is really only two controls.

---

**Q12.** A finding is: "the checkout API accepts a `price` parameter directly from the client with no server-side validation against the actual product price." Which CIA property does exploiting this **most directly** violate?

- A) Confidentiality
- B) Integrity
- C) Availability
- D) None — client-supplied prices are industry standard and safe

---

**Q13.** For the same finding as Q12, what is a defensible **impact** score, and why?

- A) 1 — cosmetic only, nothing of real value changes.
- B) 4 or 5 — an attacker could purchase products at arbitrary (including negative or zero) prices, a direct and significant financial impact.
- C) Impact can't be scored without knowing the exact dollar amount lost.
- D) Impact is always 3, by convention, for pricing-related bugs.

---

**Q14.** What is a **trust boundary**, and why does Lecture 1's breach story map to a failure at one specifically?

- A) A trust boundary is a physical firewall device; the breach story involved no such device, so this concept doesn't apply.
- B) A trust boundary is any point where data crosses between different levels of trust, requiring validation/authentication/authorization; the breach involved a missing authorization check exactly at the boundary between "any authenticated caller" and "this specific caller's own data."
- C) Trust boundaries only exist between a company and its external customers, never inside a single application.
- D) Trust boundaries are a theoretical concept with no practical engineering equivalent.

---

**Q15.** What is the **attacker/defender view**, as this course uses the term, and why is it the central discipline of the entire 12 weeks — not just Week 1?

- A) It means alternating between offense-only and defense-only weeks.
- B) It means every offensive technique studied is paired, every time, with an explicit detection and a fix — it's what keeps the course strictly defensive despite discussing real attack techniques, and it's the reasoning habit every later week (OWASP Top 10, access control, secure code review) builds on.
- C) It's a scoring system used only in the mini-project.
- D) It only applies to Week 1's material and isn't used again.

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — a threat is a potential cause of harm (an actor or event); a vulnerability is the exploitable weakness. Risk requires both together.
2. **C** — publicly exposed, trivially discoverable credentials against a live production target are highly likely to be found and used; automated tools actively scan public repos for exactly this pattern.
3. **C** — 2 × 5 = 10, which falls in the High band (10–15).
4. **B** — Integrity. Modifying data (the order total) that shouldn't be modifiable by this user is a write/tampering action, not a read — that's integrity, even though no confidential data was exposed.
5. **B** — without an exploitable weakness for the threat to act through, the threat has no path to actually cause harm; risk is the product of both, never either alone.
6. **B** — attack surface is every point where an untrusted actor could interact with the system, not a bug count, not just documented endpoints, and not a proxy for code size.
7. **B** — the endpoint was assumed to be "internal only," but that assumption was never actually enforced as a real network boundary or authorization check — an assumed-but-unenforced trust boundary, not a zero-day or a password issue.
8. **B** — spreadsheets lack schema/constraints and invite silent, untracked edits; a `findings` table in SQL gives real, repeatable, auditable queries — the reason this course's data-tooling rule exists.
9. **C** — `127.0.0.1:3000:3000` binds the published port to localhost only. Plain `3000:3000` and explicit `0.0.0.0:3000:3000` both publish to all network interfaces, making the target reachable from your whole LAN.
10. **B** — actively verify isolation (e.g., from a second device) before trusting it; assuming isolation is exactly the mistake Lecture 3 warns against, and it applies to Docker-based labs just as much as VM-based ones.
11. **B** — each control covers a distinct failure mode the other two don't; together they're what makes the course legal, safe, and honest, and dropping any one leaves a real gap.
12. **B** — Integrity. The client is able to modify data (the price) that should only be set authoritatively by the server, a tampering/write issue, not a confidentiality read.
13. **B** — a defensible impact score is high (4–5) because arbitrary or negative pricing has a direct, significant financial consequence; you don't need an exact dollar figure to justify a high score, just a clear, written rationale (which Task/Lecture 2 requires either way).
14. **B** — a trust boundary is any point where data crosses trust levels, requiring a check; the breach's real failure was a missing authorization check exactly at the boundary between "any authenticated caller" and "this specific resource's owner."
15. **B** — the attacker/defender view means every offensive concept is paired with its detection and its fix; it's the discipline that keeps this course strictly defensive and is reused, explicitly, in every remaining week.

</details>

**Scoring:** 13+ → start Week 2. 10–12 → re-read the lecture sections behind your misses. <10 → re-read all three lectures from the top; risk scoring and the attacker/defender habit compound every week from here.
