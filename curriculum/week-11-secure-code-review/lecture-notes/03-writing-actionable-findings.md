# Lecture 3 — Writing Actionable Findings

> **Duration:** ~2 hours. **Outcome:** You can turn a taint trace into a finding a developer fixes on the first read — with a precise location, a real reproduction, a stated impact, a correct severity, and a concrete source-level fix — store it in a `review_findings` table, and query that table to answer "what's still open" and "how long did this take to close."

> **Lab reminder.** Every finding written in this lecture documents a flaw in `crunch-invoices`, an app you wrote and own, confirmed against your own `127.0.0.1` instance. Writing a finding is itself defensive work — the entire purpose is to get the flaw closed before anyone else, attacker or not, reaches it.

## 1. Why most findings get ignored

A code review is only as valuable as what happens after you hit "submit." A finding that says *"the search endpoint looks like it might have a SQL injection, should probably fix"* will, in practice, get skimmed, deprioritized behind three feature deadlines, and quietly forgotten — not because the developer doesn't care, but because the finding gave them nothing to act on: no location precise enough to jump to, no proof it's real, no sense of how bad it actually is, and no specific fix to apply. **A good finding is a piece of work order, not an opinion.** It should let a developer go from reading it to opening the file to typing the fix in under two minutes, with zero back-and-forth needed to understand what you mean.

The second failure mode is just as damaging in the opposite direction: **the false alarm.** Reporting something as a vulnerability when it's actually mitigated elsewhere (a WAF rule, a database permission, a control three functions upstream you didn't trace far enough to see) burns exactly the trust a real finding needs. Every finding in this course gets **verified at the source** before it's written up — you traced it in Lecture 2, you confirmed it against the running app, and only then do you write it down. A finding without a reproduction is a suspicion, not a finding.

## 2. The finding template

Every finding this course writes has the same seven fields, always in this order:

1. **Title** — one line, specific: not "SQL injection issue" but "SQL injection in `/invoices/search` via unparameterized `WHERE` clause."
2. **Severity** — from the rubric in Section 3, stated as one word, defensible from the rubric, not a gut feeling.
3. **Location** — file, function or route, and (where it matters) the exact line or code snippet. "Somewhere in the search feature" is not a location.
4. **Description** — one to three sentences: what's wrong, and *why* it's wrong (tie it to the specific control from Lecture 1's five questions that failed).
5. **Reproduction** — the exact steps or command that demonstrates the flaw, run against your own lab instance, with the actual output you got — not a template, the real response.
6. **Impact** — what a real attacker (or, on an internal tool, a careless coworker) could actually do with this, stated concretely: "read every invoice across both customer accounts," not "could be bad."
7. **Recommended fix** — the specific code change, ideally as a diff or a named function/pattern to apply, not "add validation."

### 2.1 A worked example — writing up the injection finding

Here is the SQL injection from Lecture 2, Section 2, written the way it goes in a real report:

> **Title:** SQL injection in `GET /invoices/search` via unparameterized `customer_name`/`status` filter
>
> **Severity:** Critical
>
> **Location:** `app.py`, `build_search_query()` (called from `search_invoices()`) — the `WHERE` clause is built with an f-string: `f"customer_name LIKE '%{term}%'"` and `f" AND status = '{status_filter}'"`, then spliced into the full query with `f"... WHERE {where_clause}"`.
>
> **Description:** The `q` and `status` query-string parameters are concatenated directly into the SQL statement text instead of being bound as parameters. Because `search_invoices()` also has no session check at all (a second, independent finding — see below), this is exploitable by **anyone who can reach the route, authenticated or not.**
>
> **Reproduction:**
> ```
> $ curl -s "http://127.0.0.1:5050/invoices/search?q=x%27%20OR%20%271%27%3D%271"
> [{"id":1,"account_id":1,"customer_name":"Aperture Labs","amount_cents":452000,"status":"unpaid"}, ... all 5 rows, both accounts, no session cookie sent]
> ```
>
> **Impact:** An unauthenticated request returns every invoice, across both customer accounts (`crunch-retail` and `crunch-wholesale`), including customer names and amounts. A more targeted payload can extract arbitrary column data via `UNION SELECT` against any table the `invoices` connection can read, including the `users` table's `password_hash` column.
>
> **Recommended fix:** Replace the f-string construction with a parameterized query:
> ```python
> def search_invoices_query(term, status_filter=None):
>     sql = "SELECT id, account_id, customer_name, amount_cents, status FROM invoices WHERE customer_name LIKE ?"
>     params = [f"%{term}%"]
>     if status_filter:
>         sql += " AND status = ?"
>         params.append(status_filter)
>     return sql, params
> ```
> and add the missing `require_login()` / account filter (see the separate authorization finding).

Notice this single flaw actually produced **two findings** — the injection, and the missing authentication check — because Lecture 2 traced them as two separate control failures with two separate fixes, even though they live in the same ten-line route. **Never merge independent findings to save space.** A developer fixing the injection but not the missing login check has fixed half the problem and may reasonably believe they fixed all of it.

## 3. A severity rubric that doesn't require a CVSS calculator

This course uses a lightweight two-axis rubric, simple enough to apply consistently without a scoring tool, rigorous enough to defend in a report:

| Reach → \ Impact ↓ | Unauthenticated / any visitor | Any authenticated user | Privileged role only |
|---|---|---|---|
| **Reads or leaks data** (this account/user's own scope) | High | Medium | Low |
| **Reads or leaks data across tenants/accounts** | **Critical** | High | Medium |
| **Writes, corrupts, or deletes data** | **Critical** | High | Medium |
| **Full account takeover / arbitrary code execution** | **Critical** | **Critical** | High |

Read it as: **how far can an attacker reach without extra privilege (the row), crossed with what they can actually do once they get there (the column).** The injection finding above is Critical because it's reachable unauthenticated *and* leaks data across tenants (and, with a more advanced payload, reads arbitrary tables). The missing-role-check on `/invoices/export` is High, not Critical, because it requires *some* authenticated session — any session, but a session — before it leaks cross-tenant data. The hardcoded `SIGNING_KEY` is High on its own (anyone who reads the source or the git history can forge a valid signature for any invoice, unauthenticated, reading data across tenants) even before you account for the weak MD5 construction or the timing leak, which are separate, additional findings at Medium (they make the key easier to attack or forge under specific conditions, but the key's exposure alone is already the bulk of the damage).

## 4. Good finding vs. bad finding, side by side

| Bad finding | Why it fails | Good finding |
|---|---|---|
| "Search feature might be vulnerable to injection, please review." | No location, no proof, no fix, no severity — pure suspicion | The full write-up in Section 2.1 |
| "Export endpoint has no security." | Vague — no security *how*? Auth exists; it's authorization and tenant isolation that are missing | "`/invoices/export` checks `session` for existence only; it never reads `session[\"role\"]` or filters by `session[\"account_id\"]`, so any authenticated user of either account receives every invoice from both." |
| "Crypto is weak, use HMAC instead." | Correct direction, but skips the hardcoded-key finding entirely and doesn't name the timing issue | Three separate findings (Lecture 2, Section 4): hardcoded key (CWE-798), homemade MD5-concatenation MAC (CWE-327), non-constant-time compare (CWE-208) — each with its own fix |
| "This is a critical vulnerability!!!" with no reproduction | Alarm without evidence erodes trust in every other finding in the same report | Severity stated from the Section 3 rubric, with the reasoning ("unauthenticated reach, cross-tenant data read") spelled out in one clause |

## 5. Tracking findings in a database, not a document

Consistent with this course's data-tooling rule, every finding is a **row**, not a paragraph you'll lose track of. The `review_findings` schema this week's exercises and mini-project all use:

```sql
CREATE TABLE review_findings (
    finding_id       INTEGER PRIMARY KEY,
    app_name         TEXT NOT NULL DEFAULT 'crunch-invoices',
    location         TEXT NOT NULL,       -- e.g. 'app.py:search_invoices'
    cwe              TEXT NOT NULL,       -- e.g. 'CWE-89'
    category         TEXT NOT NULL CHECK (category IN
        ('injection','authn','authz','crypto','secrets','config','other')),
    severity         TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    reproduction     TEXT NOT NULL,
    impact           TEXT NOT NULL,
    recommended_fix  TEXT NOT NULL,
    discovered_by    TEXT NOT NULL,
    discovered_at    TEXT NOT NULL DEFAULT (datetime('now')),
    status           TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','fixed','wontfix','false_positive','retested_ok')),
    resolved_at      TEXT
);
```

```sql
INSERT INTO review_findings
    (location, cwe, category, severity, title, description, reproduction, impact, recommended_fix, discovered_by)
VALUES
    ('app.py:search_invoices/build_search_query', 'CWE-89', 'injection', 'critical',
     'SQL injection in GET /invoices/search via unparameterized WHERE clause',
     'q and status query params are spliced into the WHERE clause with an f-string instead of bound as parameters.',
     'curl "http://127.0.0.1:5050/invoices/search?q=x%27%20OR%20%271%27%3D%271" returned all 5 invoices, both accounts, no session cookie sent',
     'Unauthenticated read of all invoice data across both tenant accounts; extensible to arbitrary table reads via UNION SELECT.',
     'Bind term and status_filter as ? parameters instead of splicing into the SQL string; see search_invoices_query() in Lecture 2 Section 2.',
     'you');
```

Once findings are rows, the questions that matter about a review answer themselves in SQL instead of a status meeting:

```sql
-- Everything still open, worst first
SELECT finding_id, severity, title
FROM review_findings
WHERE status = 'open'
ORDER BY CASE severity
    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;

-- Count by category -- which control area needed the most fixes this review?
SELECT category, COUNT(*) FROM review_findings GROUP BY category ORDER BY COUNT(*) DESC;

-- Time to close, for everything already resolved
SELECT finding_id, title,
       julianday(resolved_at) - julianday(discovered_at) AS days_to_fix
FROM review_findings
WHERE status IN ('fixed','retested_ok') AND resolved_at IS NOT NULL
ORDER BY days_to_fix DESC;
```

A finding's lifecycle in this course is always **`open` → `fixed` (a diff exists) → `retested_ok` (you re-ran the exact reproduction from the row and it now behaves correctly)** — mirroring the demonstrate → remediate → re-test loop Week 6 introduced for authorization findings. `wontfix` and `false_positive` exist as honest outcomes too: not every finding gets fixed (a risk may be formally accepted) and not every suspicion survives verification (Lecture 2's discipline of confirming before writing exists precisely to keep this status rare).

## 6. Check yourself

- Why does the injection finding in Section 2.1 count as *two* findings instead of one, even though both live in the same route?
- Using the Section 3 rubric, what severity would you assign a flaw that lets any authenticated user (any role) read another account's invoice list, and why that cell specifically?
- What's wrong with "Crypto is weak, use HMAC instead" as a finding, even though the recommendation itself is correct?
- Why does a finding require a reproduction *before* it's written up, rather than being reported the moment you suspect something from reading the code?
- What are the five lifecycle states a row in `review_findings` can hold, and what does each one mean in practice?
- Write, from memory, the seven fields every finding in this course must include.

If those are automatic, Exercise 3 has you take every flaw traced in Exercise 2 and write the full seven-field finding for each, insert it into `review_findings.db`, and run the summary queries from Section 5 against your own data.

## Further reading

- **OWASP — Vulnerability reporting and remediation guidance:** <https://owasp.org/www-project-vulnerability-report/>
- **CWE — Common Weakness Enumeration (browse by category):** <https://cwe.mitre.org/data/index.html>
- **FIRST — Common Vulnerability Scoring System (CVSS) v3.1 specification** (for when a course-level rubric isn't enough): <https://www.first.org/cvss/v3.1/specification-document>
- **HackerOne — "How to Write a Great Vulnerability Report":** <https://www.hackerone.com/vulnerability-management/how-write-great-vulnerability-report>
