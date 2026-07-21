# Week 3 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 4. A mix of multiple-choice and short "what category is this" questions — the answer key at the bottom explains the *why*, not just the letter.

---

**Q1.** The OWASP Top 10 (2021) ranking was built primarily from:

- A) A single security vendor's internal bug tracker
- B) Contributed, anonymized testing data across many organizations, combined with a practitioner survey
- C) A vote among Fortune 500 CISOs
- D) Automated scanner output from one tool

---

**Q2.** Why did Broken Access Control move to #1 in the 2021 list?

- A) It became a brand-new category that year
- B) Its incidence rate in the contributed testing data grew, pushing its rank up even though the vulnerability class itself wasn't new
- C) OWASP decided alphabetically
- D) Injection was removed from the list entirely

---

**Q3.** This code is vulnerable to which category?

```python
row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```

(no check that `note_id` belongs to the current session's user)

- A) A03 Injection
- B) A01 Broken Access Control (IDOR)
- C) A02 Cryptographic Failures
- D) A10 SSRF

---

**Q4.** A route correctly checks `if "user_id" not in session` but never checks the user's `role` before returning admin-only data. This is:

- A) An IDOR
- B) Missing function-level access control
- C) Insecure Design
- D) Not a vulnerability, since the user is authenticated

---

**Q5.** Why is MD5 unsuitable for hashing passwords, even though it's fine for a file checksum?

- A) MD5 doesn't exist in Python
- B) MD5 is fast and unsalted, making it trivially brute-forceable and vulnerable to precomputed rainbow tables
- C) MD5 always produces the same output length as the input
- D) MD5 requires a paid license

---

**Q6.** `sql = f"SELECT * FROM notes WHERE title LIKE '%{q}%'"` is vulnerable because:

- A) f-strings are deprecated in Python
- B) The database can't tell developer-written SQL apart from user-supplied text once they're concatenated into one string
- C) `LIKE` is inherently insecure and should never be used
- D) SQLite doesn't support f-strings

---

**Q7.** The correct fix for the query in Q6 is:

- A) Escape the `%` character manually
- B) Use a `?` placeholder and pass `q` as a bound parameter
- C) Reject any input containing the letter "O"
- D) Switch from SQLite to a NoSQL database

---

**Q8.** `crunch-notes`'s `/notes/export` route has no size or pagination limit anywhere in the schema or the route. This is best classified as:

- A) A03 Injection, because it involves a database query
- B) A04 Insecure Design, because the missing constraint is an absent requirement, not a coding mistake in an existing check
- C) A07 Authentication Failure
- D) Not a vulnerability, since the query is parameterized correctly

---

**Q9.** What's the key difference between A02/A03 style fixes and the A04 fix in this week's lectures?

- A) A04 doesn't need a fix at all
- B) A02/A03 fixes correct a specific wrong line of code; the A04 fix required adding a constraint that was never designed in anywhere, including the schema
- C) A04 is fixed entirely in the frontend
- D) There is no meaningful difference

---

**Q10.** `debug=True` in a Flask app reachable beyond your own machine is dangerous chiefly because:

- A) It makes the app run slower
- B) It can expose source code, environment values, and an interactive code-execution console via the Werkzeug debugger on any unhandled exception
- C) It disables HTTPS
- D) It's only a cosmetic issue affecting error page styling

---

**Q11.** `pip-audit` is used to:

- A) Format your Python code
- B) Cross-reference your pinned dependency versions against a public vulnerability advisory database
- C) Encrypt your `requirements.txt`
- D) Automatically upgrade every dependency to the newest version regardless of breaking changes

---

**Q12.** Why is a brute-force lockout on `/login` an A07 (Authentication Failure) concern rather than an A03 (Injection) concern?

- A) It isn't a real vulnerability
- B) No untrusted input is being interpreted as code; the flaw is the absence of a control on repeated identity-verification attempts, which is what A07 covers
- C) A03 only applies to SQL, and login forms never touch SQL
- D) Brute force is only relevant to A10

---

**Q13.** `pickle.loads()` on content fetched from a URL the caller supplied is dangerous because:

- A) `pickle` files are always larger than JSON files
- B) Pickle's `__reduce__` mechanism can encode arbitrary object construction, including running OS commands, so unpickling untrusted bytes can execute attacker-chosen code
- C) `pickle` is deprecated in Python 3
- D) It only affects performance, not security

---

**Q14.** Why does A09 (Logging and Monitoring Failures) get demonstrated by an *absence* in `crunch-notes` rather than one specific bad line of code?

- A) It's a trick question — A09 isn't a real category
- B) The vulnerability *is* the absence of a control (no record of security-relevant events anywhere), so there's no single line to point at — only a missing one
- C) Logging failures can only happen in compiled languages
- D) `crunch-notes` actually has extensive logging already

---

**Q15.** Why is a strict allowlist the correct fix for the SSRF in `/avatar`, rather than a blocklist of known-bad hosts like `127.0.0.1` and `localhost`?

- A) Allowlists are always faster to execute
- B) A blocklist can always be bypassed by a form the list-writer didn't anticipate (alternate loopback notations, DNS rebinding, etc.); an allowlist denies everything not explicitly permitted, closing the whole class of bypass at once
- C) Blocklists are illegal under GDPR
- D) There is no meaningful difference between the two approaches

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — contributed, anonymized testing data (~60% weight) combined with a practitioner survey (~40% weight), per Lecture 1, Section 2.
2. **B** — the categories aren't static; a category's *rank* moves as its real-world incidence rate changes in the data, even when the vulnerability class itself is old.
3. **B** — an object is looked up by a client-supplied ID with no check that the requesting user actually owns/may access it: the textbook IDOR.
4. **B** — this is specifically the "missing function-level access control" sub-pattern, distinct from an IDOR (which is about the wrong *object*, not the wrong *function*).
5. **B** — MD5 is fast (billions of guesses/sec on modern hardware) and, without a salt, identical passwords produce identical hashes, enabling rainbow-table attacks.
6. **B** — once user input is concatenated into the SQL string, the database has no way to distinguish "text the developer intended as a literal" from "text that changes the query's structure."
7. **B** — parameterized queries (`?` placeholders with bound values) let the database enforce the code/data boundary itself, rather than relying on manual escaping.
8. **B** — the query itself is correctly parameterized and correctly scoped; the flaw is that no size/pagination limit was ever specified as a requirement, which is exactly what makes it Insecure Design rather than an implementation bug.
9. **B** — A02/A03 are "wrong code, known correct pattern exists"; A04 required going back to the schema to add a constraint that should have existed from the start, which no code review of the route alone would have caught.
10. **B** — the Werkzeug interactive debugger, triggered by any unhandled exception, can expose source, local variables (including secrets), and a live Python console.
11. **B** — `pip-audit` checks your exact pinned versions against a public advisory database and reports known vulnerabilities; it doesn't format code or auto-upgrade anything by itself.
12. **B** — A07 covers weaknesses in identity-verification controls themselves (rate limiting, lockout, session handling); no interpreter is being tricked into executing anything, which is what would make it A03.
13. **B** — pickle's object-reconstruction hooks (like `__reduce__`) can be crafted to run arbitrary code during deserialization, which is why untrusted pickle input is a code-execution vector, not just a data-parsing risk.
14. **B** — A09's defining trait is that the vulnerability is a missing control, not a flawed one; there's no single bad line because nothing was ever written.
15. **B** — blocklists are inherently incomplete (there's always another bypass form); an allowlist flips the default to deny, closing every unanticipated variant at once.

</details>

**Scoring:** 12+ → start Week 4. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; Weeks 4–7 assume this vocabulary is automatic.
