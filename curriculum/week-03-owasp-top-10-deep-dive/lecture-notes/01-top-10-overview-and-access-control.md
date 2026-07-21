# Lecture 1 — The Top 10 Overview, and Broken Access Control in Depth

> **Duration:** ~2 hours. **Outcome:** You can explain how the OWASP Top 10 list is built and why it changes over time; you can define Broken Access Control precisely, recognize IDOR and missing function-level checks as code patterns, and you have demonstrated and fixed both against `crunch-notes`.

## 1. What the OWASP Top 10 actually is

The **OWASP Top 10** is a periodically updated ranking of the ten most critical web application security risk *categories*, published by the Open Worldwide Application Security Project — a nonprofit, volunteer-run, vendor-neutral community. It is not a top-10 list of specific bugs; it's a **taxonomy of categories**, each one covering a family of related vulnerabilities that share a root cause and a typical fix.

It matters for three concrete reasons:

1. **Shared vocabulary.** When a penetration test report, a bug bounty submission, a CVE writeup, or a colleague says "A01," everyone in the industry knows roughly what class of problem is meant, without re-explaining it from scratch every time.
2. **Compliance and contracts.** PCI-DSS, SOC 2, and countless vendor security questionnaires reference the OWASP Top 10 by name. "We test against the OWASP Top 10" is a specific, checkable claim, not marketing language.
3. **A prioritization signal, not a complete list.** The Top 10 covers the categories responsible for the largest share of real-world impact — it does **not** mean a vulnerability outside the ten doesn't matter. Treat it as "the highest-value ten," not "the only ten."

## 2. How the list is built

The current list (2021, the version this course uses) was built from two combined data sources — worth knowing because it explains *why* the categories are shaped the way they are:

- **Contributed data.** Organizations submitted anonymized vulnerability testing data — hundreds of thousands of applications, tens of millions of findings — categorized by CWE (Common Weakness Enumeration, the more granular vulnerability taxonomy the Top 10 sits on top of). This drove roughly 60% of category selection, ranked by **incidence rate** — how often the category showed up at all.
- **Community survey.** Practitioners were surveyed on which risks they believed were on the rise or under-represented in the testing data, because testing data lags behind what's actually happening in the wild (a category can be under-tested for precisely because it's new or hard to find automatically). This drove the remaining ~40%, weighted toward *exploitability* and *impact* rather than raw frequency.

The two data sources were then combined and ranked, roughly, by:

```
Category rank ≈ f(incidence rate, exploitability, detectability, technical impact)
```

This is why the list **reorders between editions** even when the underlying vulnerability classes don't change much — "Injection" was #1 in 2017 and dropped to #3 in 2021 not because injection got less dangerous, but because **Broken Access Control's incidence rate in the contributed testing data grew faster**, pushing it to #1. The categories also get **restructured**, not just re-ranked: 2021 folded "Sensitive Data Exposure" into the broader "Cryptographic Failures" (the *cause*, not the *symptom*), and introduced a brand-new "Insecure Design" category because enough real-world findings were architectural, not implementation, bugs.

## 3. The OWASP Top 10 (2021) — the full list at a glance

This week's map. Categories 1–3 get a full lecture each (this one and the next); 4–10 get a demo-and-fix survey in Lecture 3.

| # | Category | One-line pattern |
|---|---|---|
| **A01** | Broken Access Control | A check for "is this user allowed to do *this*, to *this specific object*" is missing or wrong |
| **A02** | Cryptographic Failures | Sensitive data is stored or transmitted with weak, missing, or misused cryptography |
| **A03** | Injection | Untrusted input is interpreted as code/commands by an interpreter (SQL, shell, etc.) |
| **A04** | Insecure Design | The vulnerability is a missing security *requirement*, not a coding mistake |
| **A05** | Security Misconfiguration | A secure option existed and wasn't turned on, or a debug/default setting shipped to production |
| **A06** | Vulnerable and Outdated Components | A dependency with a known vulnerability is running in your app |
| **A07** | Identification and Authentication Failures | Login, session, or identity-proofing controls can be bypassed or brute-forced |
| **A08** | Software and Data Integrity Failures | Code or data is trusted without verifying its origin or that it wasn't tampered with |
| **A09** | Security Logging and Monitoring Failures | An attack happens and nobody — human or system — ever finds out |
| **A10** | Server-Side Request Forgery (SSRF) | The server is tricked into making a request to a destination the attacker chose |

## 4. A01 — Broken Access Control: the precise definition

**Broken access control** means the application fails to enforce that an authenticated (or anonymous) user is permitted to perform the specific action they're attempting, on the specific object they're attempting it on. It is 2021's #1 category by incidence rate — it showed up in a larger share of tested applications than any other category — which makes it the right place to start.

Access control has exactly two questions it must answer correctly, every single time, for every request:

1. **Authentication: who is making this request?** (Often correct — most apps do check *this*.)
2. **Authorization: is *this specific* identity allowed *this specific* action on *this specific* object?** (Frequently missing, or checked once and forgotten on a second code path.)

Broken access control is what happens when question 1 gets answered but question 2 doesn't. Two sub-patterns account for the overwhelming majority of real findings, and both live in `crunch-notes`:

### 4a. IDOR — Insecure Direct Object Reference

An **IDOR** happens when an application uses a value the client controls (a URL parameter, a form field, a hidden input) to look up an object directly, without checking that the *current* user is allowed to access *that particular* object.

`crunch-notes`'s `/notes/<note_id>` route is a textbook IDOR:

```python
@app.route("/notes/<note_id>")
def get_note(note_id):
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    # VULNERABLE (A01) — no check that this note belongs to session['user_id']: IDOR
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
```

The bug is not the SQL — it's parameterized correctly (that's Lecture 2's problem, not this one). The bug is that the query **never mentions `session["user_id"]` at all**. Any logged-in user can substitute any `note_id` and read anyone's note. Note the shape: the code checks *authentication* (`"user_id" not in session`) and stops there, silently treating "logged in" as equivalent to "authorized for this object" — which is exactly the confusion the two-question framework above exists to prevent.

**Demonstrate it** (both users already exist from `seed.py`):

```bash
# log in as alice, keep her session cookie
curl -s -c alice.txt -X POST http://127.0.0.1:5000/login -d "username=alice&password=alice-pass"

# alice reads her own note (id 1) — expected, fine
curl -s -b alice.txt http://127.0.0.1:5000/notes/1

# alice reads bob's note (id 2) — she was never granted this, and gets it anyway
curl -s -b alice.txt http://127.0.0.1:5000/notes/2
```

The second request returns Bob's admin runbook to Alice's session. That's the flaw, proven with two `curl` commands and no guessing.

**Remediate it** — the fix is one added clause, because the fix for an IDOR is almost always "add the ownership predicate you forgot":

```python
@app.route("/notes/<note_id>")
def get_note(note_id):
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    row = db.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
```

**Re-test:** re-run the exact same `curl -b alice.txt http://127.0.0.1:5000/notes/2` command. It must now return `{"error":"not found"}` with a 404 — not a 403. Returning 404 instead of "403 forbidden, this belongs to someone else" is deliberate: a 403 confirms to an attacker that note ID 2 *exists* and belongs to somebody; a uniform 404 for "doesn't exist" and "not yours" leaks nothing extra. This is why the fixed query filters by both columns in one predicate instead of doing a first lookup-by-id followed by a second ownership check with a different error message.

### 4b. Missing function-level access control

A subtler variant: the object-level check might be fine, but the **endpoint itself** should only be reachable by a certain role, and nothing enforces that.

```python
@app.route("/admin/users")
def admin_users():
    # VULNERABLE (A01) — checks login, never checks role: missing function-level access control
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
```

This one is arguably worse than the IDOR above: it's not "wrong object," it's **"wrong function entirely."** Any authenticated user — Alice, a brand-new signup, anyone — can list every username, role, and account in the system, because the route only asks "are you logged in," never "are you an admin." This exact pattern is what let the intern in Lecture 1 of Week 1 reach an internal-only endpoint from the public internet — a missing check at exactly this kind of boundary.

**Demonstrate it:**

```bash
# alice is a regular user (role='user' in seed.py), not an admin
curl -s -b alice.txt http://127.0.0.1:5000/admin/users
```

This returns the full user table — including Bob's `admin` role — to a non-admin account.

**Remediate it** with an explicit, deny-by-default role check:

```python
def require_role(role):
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    db = get_db()
    row = db.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if row is None or row["role"] != role:
        return jsonify(error="forbidden"), 403
    return None  # None means "checks passed, continue"


@app.route("/admin/users")
def admin_users():
    denial = require_role("admin")
    if denial:
        return denial
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
```

**Re-test:** the same `curl -b alice.txt http://127.0.0.1:5000/admin/users` must now return `{"error":"forbidden"}` with a 403. Then confirm the fix doesn't over-correct — log in as Bob and confirm `admin/users` still works for him:

```bash
curl -s -c bob.txt -X POST http://127.0.0.1:5000/login -d "username=bob&password=bob-pass"
curl -s -b bob.txt http://127.0.0.1:5000/admin/users   # must still succeed for bob
```

A fix that blocks *everyone*, including legitimate admins, isn't a fix — it's a different bug, and re-testing the positive case (Bob still works) is exactly as important as re-testing the negative case (Alice still fails).

## 5. The pattern behind both sub-patterns

Notice that both the IDOR and the missing-function-check share one root cause: **the code answered "is this person logged in" and treated that as a complete answer to "is this person allowed to do this."** Every fix in this section is some version of "add the specific check that was missing" — never a broad, vague `# TODO: add security` — because access control bugs are found and fixed one specific missing predicate at a time. Two more principles worth internalizing now, before Week 6 goes much deeper on them:

- **Deny by default.** Access should be denied unless a rule explicitly grants it, never granted unless a rule explicitly denies it. `require_role` above returns `403` the instant the check fails — it never falls through to "allow."
- **Check at the point of use, not the point of entry.** A check performed once at login (or in client-side JavaScript) protects nothing on the server. Every route that touches a specific object re-checks ownership; every route that requires a role re-checks the role — on the server, on every request.

## 6. Check yourself

- In one sentence, what's the difference between an IDOR and a missing function-level access control check?
- Why does the fixed `/notes/<note_id>` route return 404 for "not yours" instead of 403?
- What are the two questions every access-control check must answer, and which one does an IDOR usually get wrong?
- Why is "deny by default" safer than "allow by default, deny the exceptions"?
- Name one other endpoint in `crunch-notes/app.py` (Lecture 2 or 3's territory) where you'd want to ask "who is this checking, and against what object?"

Lecture 2 moves to the two categories with the highest blast radius when they do go wrong — cryptographic failures and injection — plus the newest category on the list, insecure design.

## Further reading

- **OWASP Top 10:2021 — A01 Broken Access Control:** <https://owasp.org/Top10/A01_2021-Broken_Access_Control/>
- **OWASP — How the Top 10 is built (methodology):** <https://owasp.org/Top10/A00_2021_Methodology_and_Data/>
- **CWE-639 — Authorization Bypass Through User-Controlled Key (the formal name for IDOR):** <https://cwe.mitre.org/data/definitions/639.html>
- **OWASP Cheat Sheet — Authorization:** <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
