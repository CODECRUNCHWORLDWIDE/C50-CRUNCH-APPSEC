# Week 2 — Quiz

Fifteen questions. Lectures closed. Aim for 13/15 before starting Week 3. A mix of multiple-choice and short "what would you do here" questions — the answer key explains the *why*, not just the letter.

---

**Q1.** In a data-flow diagram, which of the following is **never** allowed?

- A) An external entity sending a flow into a process
- B) A process reading from a data store
- C) A data flow connecting two data stores directly, with no process between them
- D) A data flow crossing a trust boundary

---

**Q2.** A trust boundary is best defined as:

- A) The physical wall of the data center
- B) A place on the diagram where the level of trust changes — control or privilege changes hands
- C) Any line drawn between two processes
- D) The boundary of the company's legal jurisdiction

---

**Q3.** Why do threats cluster at trust boundaries?

- A) They don't — threats are evenly distributed across a diagram
- B) Boundaries are where an attacker gets to inject something the system didn't expect, because control or privilege is changing hands
- C) Trust boundaries only exist in Level 2 diagrams
- D) Boundaries always indicate a Denial of Service threat specifically

---

**Q4.** What does the "S" in STRIDE stand for, and which security property does it violate?

- A) Spoofing — authentication
- B) Sabotage — availability
- C) Snooping — confidentiality
- D) Scaling — availability

---

**Q5.** Which STRIDE category never applies to a data store?

- A) Tampering
- B) Information Disclosure
- C) Spoofing
- D) Denial of Service

---

**Q6.** Why does a **process** get checked against all six STRIDE categories, while an **external entity** gets checked against only Spoofing and Repudiation?

- A) It's an arbitrary convention with no underlying reason
- B) A process is where logic executes, so every property can be violated by flawed logic; an external entity is outside your control, so you can only ask whether it can be impersonated or can deny an action
- C) External entities are always more secure than processes
- D) Processes are always slower, so they need more checks

---

**Q7.** A login form shows "invalid password" when the password is wrong but "no account with that email" when the email doesn't exist. Which STRIDE category does this threat belong to?

- A) Tampering
- B) Repudiation
- C) Information Disclosure
- D) Denial of Service

---

**Q8.** Risk, as used in this week's scoring method, is calculated as:

- A) Likelihood + Impact
- B) Likelihood × Impact
- C) Impact only
- D) Likelihood only

---

**Q9.** A threat with likelihood 5 and impact 5 gets which disposition, necessarily?

- A) Always "accept," because it's too big to fix
- B) None is implied by the score alone — disposition (mitigate/eliminate/transfer/accept) is a separate judgment call informed by, but not determined by, the risk score
- C) Always "eliminate"
- D) Always "transfer"

---

**Q10.** Which of the following is a **valid** use of the "accept" disposition?

- A) A team ignores a threat because the list was too long to review
- B) A team documents, with a named decision-maker, that a risk-6 threat won't be addressed this quarter and will be revisited next quarter
- C) A developer forgets to triage a threat at all
- D) A threat is left with no disposition assigned

---

**Q11.** Why does this course require threat models to be stored in SQLite/Python rather than a spreadsheet?

- A) Spreadsheets can't store text
- B) A structured, queryable store lets you ask "what's my top 5 open risk?" or "how many open threats per STRIDE category?" as a repeatable query, and keeps a generated report from silently drifting out of sync with the underlying data
- C) SQLite is required by law for security data
- D) Spreadsheets cannot be version-controlled at all

---

**Q12.** What is the key difference between threat modeling and penetration testing?

- A) They answer the same question; threat modeling is just the cheaper version
- B) Threat modeling reasons about what *could* go wrong given a design, usable before code exists; penetration testing verifies whether something *does* go wrong in a running system
- C) Penetration testing always happens first, then threat modeling
- D) Threat modeling requires special tools; penetration testing requires none

---

**Q13.** In an attack tree, an **AND** node means:

- A) Any one child branch is sufficient for the attacker to succeed
- B) All child branches must succeed for the parent goal to be achieved
- C) The node is a data store
- D) The node represents a mitigated threat

---

**Q14.** According to Lecture 3's guidance on avoiding analysis paralysis, when should you explode a Level 1 process into a Level 2 diagram?

- A) Always, for every process, to be thorough
- B) Never — Level 2 diagrams are not part of this course's method
- C) When that process's STRIDE pass surfaces a high-risk threat worth examining more closely — depth should follow risk, not curiosity
- D) Only if the process has fewer than three data flows

---

**Q15.** A team's server-side code for an admin-only route only checks "is this user logged in," not "is this user's role actually admin." Which STRIDE category does this missing check represent, and which future week of this course teaches the fix?

- A) Denial of Service; Week 9
- B) Elevation of Privilege; Week 6 (access control)
- C) Repudiation; Week 11
- D) Spoofing; Week 4

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **C** — a data flow must always pass through a process; skipping it hides exactly where a bug usually lives (Lecture 1, Section 6).
2. **B** — a trust boundary marks where control or privilege changes, not a physical or legal boundary.
3. **B** — crossing a boundary is exactly where an attacker's input first meets code that has to make a trust decision.
4. **A** — Spoofing violates authentication: can someone pretend to be who they're not.
5. **C** — Spoofing never applies to a data store (or a data flow) — you don't authenticate *to* inert data, only to an actor (a process or an external entity).
6. **B** — the STRIDE-per-element table's shape follows directly from what each element type actually *is*: an actor (spoof/repudiate), executing logic (all six), or inert data (tamper/disclose/deny-service, never spoof).
7. **C** — this leaks information (which emails have accounts) that shouldn't be distinguishable from a failed-password case.
8. **B** — risk = likelihood × impact, the formula used throughout Lecture 3.
9. **B** — a high score tells you the threat is severe, but disposition is a separate decision about *how* to respond, made with the same rigor regardless of score.
10. **B** — accept must be a documented, deliberate decision by someone with authority; A, C, and D are all just unaddressed risk without the label.
11. **B** — the point of structured storage is repeatable queries and a single source of truth a generated report can't silently drift from.
12. **B** — threat modeling is design-time reasoning about possibility; penetration testing is runtime verification of actuality. Neither substitutes for the other.
13. **B** — AND requires every child branch to succeed; OR (not this question's answer) means any one suffices.
14. **C** — depth follows risk: explode a process to Level 2 only when its Level 1 STRIDE pass turns up something worth a closer look, not by default.
15. **B** — this is Elevation of Privilege (a normal user gains admin-level access because authorization was never actually checked), and Week 6 (access control, deny-by-default authorization) is where you build the fix.

</details>

**Scoring:** 13+ → start Week 3. 10–12 → re-read the lecture sections behind your misses. <10 → re-read all three lectures from the top; STRIDE-per-element is the method every remaining week of this course assumes you have.
