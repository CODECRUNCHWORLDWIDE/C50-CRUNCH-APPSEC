# Week 5 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 6. A mix of multiple-choice and short "what would happen" questions — the answer key explains the *why*, not just the letter.

---

**Q1.** The single underlying condition that makes injection possible, across SQL, shell, LDAP, and template contexts, is:

- A) The developer forgot to use HTTPS
- B) Untrusted data crosses into an interpreter without being kept separate from the instructions
- C) The database doesn't have a firewall in front of it
- D) The application uses too many library dependencies

---

**Q2.** Given `f"WHERE username = '{username}' AND password = '{password}'"`, which `username` value causes the password check to be discarded entirely?

- A) `admin`
- B) `' OR 1=1`
- C) `admin'-- `
- D) `<script>alert(1)</script>`

---

**Q3.** Why is `SELECT username FROM users WHERE id = {user_id}` (no quotes around the placeholder) still injectable, even though there's no quote character for the attacker to "break out of"?

- A) It isn't injectable — no quotes means no injection risk
- B) The numeric context has no delimiter at all, so any SQL syntax typed there becomes part of the query directly
- C) SQLite ignores numeric WHERE clauses
- D) Only string columns can be injected

---

**Q4.** A parameterized query is safe because:

- A) The database encrypts the query before running it
- B) The query structure is parsed separately from, and before, the data values are substituted in as literal values
- C) It automatically removes all special characters from the input
- D) It runs the query twice to check for consistency

---

**Q5.** Which of these is a correct, safe use of SQLAlchemy's `text()`?

- A) `text(f"SELECT * FROM users WHERE username = '{username}'")`
- B) `text("SELECT * FROM users WHERE username = '" + username + "'")`
- C) `text("SELECT * FROM users WHERE username = :u"), {"u": username}`
- D) `text("SELECT * FROM users WHERE username = %s" % username)`

---

**Q6.** Escaping input by hand (e.g., doubling `'` characters) is not a sufficient primary defense against SQL injection because:

- A) It's too slow at runtime to matter
- B) It's context-dependent, easy to apply inconsistently, and doesn't protect against second-order injection the way parameterization does
- C) Modern databases ignore escaped characters
- D) It only works on PostgreSQL, not SQLite

---

**Q7.** `os.popen(f"ping -c 1 {host}")` with `host = "127.0.0.1; whoami"` results in:

- A) A syntax error, because `;` isn't valid in a hostname
- B) `ping` running with a garbled hostname argument and failing safely
- C) Two separate shell commands executing: `ping -c 1 127.0.0.1` and then `whoami`
- D) Nothing — Python strips shell metacharacters automatically

---

**Q8.** The core reason an **allowlist** validator is preferred over a **blocklist** for the `/diagnostics/ping` host field is:

- A) Allowlists run faster
- B) A blocklist must anticipate every dangerous pattern in advance; an allowlist only needs to define what a valid hostname/IP looks like, rejecting everything else by default
- C) Blocklists are deprecated in Python 3.10+
- D) Allowlists don't require any code at all

---

**Q9.** `subprocess.run(["ping", "-c", "1", host])` (list form, no `shell=True`) is safer than `os.popen(f"ping -c 1 {host}")` because:

- A) It runs faster
- B) There is no shell involved at all, so shell metacharacters in `host` have no interpreter left to mean anything to
- C) It automatically validates `host` for you
- D) It only works with IP addresses, not hostnames

---

**Q10.** What distinguishes **stored** XSS from **reflected** XSS?

- A) Stored XSS only affects the attacker's own browser
- B) Reflected XSS requires a database; stored XSS doesn't
- C) Stored XSS persists (e.g., in a database) and can fire for every later visitor; reflected XSS requires the victim to submit or click a crafted request right now
- D) There is no meaningful difference

---

**Q11.** In Crunch Notes, removing `|safe` from `{{ n['body'] }}` fixes the stored XSS because:

- A) It deletes the malicious note from the database
- B) Jinja2's default autoescaping HTML-entity-encodes the value once `|safe` no longer disables it, so `<script>` renders as literal text instead of a parsed element
- C) It blocks the `/notes/new` route entirely
- D) `|safe` only affects CSS, not HTML

---

**Q12.** Why is DOM-based XSS (like VULN #7 in `/welcome`) not fixed by server-side output encoding?

- A) DOM XSS only affects Internet Explorer
- B) The vulnerable data flow (URL → JavaScript → `innerHTML`) never touches the server at all — the fix has to live in the client-side JavaScript
- C) DOM XSS is not a real vulnerability class
- D) Server-side encoding is always sufficient; the premise is false

---

**Q13.** Content Security Policy (CSP) is best described as:

- A) The primary fix for XSS, replacing output encoding
- B) A defense-in-depth layer enforced by the browser that can stop an XSS payload from executing even if it slipped past encoding, but does not fix the underlying encoding bug
- C) A server-side input validation library
- D) A replacement for parameterized queries

---

**Q14.** In a **boolean-blind** SQL injection against an endpoint that only ever returns `"User found."` or `"Not found."`, the attacker's one bit of signal per request comes from:

- A) An error message revealing the query structure
- B) The exact data value being reflected back
- C) Which of the two fixed responses came back for a given injected condition
- D) The HTTP status code always being 500 on success

---

**Q15.** A **time-based** blind SQL injection payload like `' OR sleep(3)-- ` proves the injection point is exploitable when:

- A) The response returns an error
- B) The response takes measurably longer than a normal request, roughly matching the injected delay
- C) The response is always exactly 3 bytes shorter
- D) The server crashes

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — every context in this week (SQL, shell, LDAP, templates) shares this one root cause: data and instructions aren't kept separate across a trust boundary.
2. **C** — `admin'-- ` closes the username's quote and comments out everything after it, including the password check, with SQL's `--` comment syntax.
3. **B** — with no quotes at all, there's nothing to "escape out of" in the first place; any valid SQL syntax typed in that position becomes part of the query directly, which is exactly why "the fix is escaping quotes" is a category error.
4. **B** — the database parses the query structure first, with placeholders standing in for not-yet-arrived values; the data is bound in afterward, purely as literal values, never re-parsed as syntax.
5. **C** — bound `:u` parameter passed as a separate dict. A, B, and D all build the SQL text by string interpolation before it reaches `text()`, defeating the point of using it.
6. **B** — escaping is context-dependent and easy to apply inconsistently (miss one query, one context, one code path and you're exposed), and a value escaped on the way in doesn't protect a second query built later from data already stored unescaped in the database (second-order injection). Parameterization has neither problem.
7. **C** — `;` is a shell command separator; the shell runs `ping -c 1 127.0.0.1`, then separately runs `whoami`.
8. **B** — a blocklist must guess every dangerous pattern in advance and will always miss one; an allowlist just defines the (much smaller, well-understood) shape of valid input and rejects everything else by default, including patterns nobody thought of.
9. **B** — list-form `subprocess.run` never invokes `/bin/sh` to parse the command, so there is no interpreter present for `;`, `&&`, backticks, etc. to mean anything to.
10. **C** — stored XSS is saved (e.g., to a database) and fires for every subsequent visitor who loads the page; reflected XSS needs a victim to submit/click the malicious payload in the current request.
11. **B** — Jinja2 autoescapes by default; `|safe` was the only thing suppressing that. Removing it restores HTML-entity encoding on that value.
12. **B** — the attacker-controlled data (`location.search`) is read and written into the DOM entirely inside the browser's own JavaScript; the server never sees or handles this data at all in the DOM XSS case, so server-side fixes are irrelevant to it.
13. **B** — CSP is a browser-enforced, defense-in-depth backstop, not a substitute for getting output encoding right in the first place.
14. **C** — the only signal is which of the two possible fixed responses the server sent back for a given injected true/false condition; there's no error text or data value involved.
15. **B** — an unusually long response time, roughly matching the injected delay, is the entire signal in a time-based blind technique — no error, no data, no length difference to rely on.

</details>

**Scoring:** 12+ → start Week 6. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; injection is the highest-leverage vulnerability class in this entire course, worth getting solid before moving on.
