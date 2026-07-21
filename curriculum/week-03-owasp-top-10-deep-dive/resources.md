# Week 3 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific category or question comes up.

## Install first (if you haven't already)

- **Python 3.10+** — `crunch-notes` and every script this week runs on it: <https://www.python.org/downloads/>
- **`pip-audit`** — the dependency-vulnerability scanner used in Lecture 3: `pip install pip-audit`
- **Your Week 1 Docker lab** — Juice Shop, DVWA, WebGoat, still running from `lab-setup.sh`: confirm with `docker ps --filter network=appsec-lab`.

## Required reading (this week's core)

- **OWASP Top 10:2021 — full list, landing page:** <https://owasp.org/Top10/>
  *Why: the canonical, current version of the list this whole week is built on. Read the one-paragraph overview for each of the ten before Lecture 1.*
- **OWASP — Top 10:2021 Methodology and Data:** <https://owasp.org/Top10/A00_2021_Methodology_and_Data/>
  *Why: exactly how the list is built — Lecture 1, Section 2's source.*
- **OWASP Top 10:2021 — A01 Broken Access Control:** <https://owasp.org/Top10/A01_2021-Broken_Access_Control/>
  *Why: the official definition and real-world example set behind Lecture 1.*
- **OWASP Top 10:2021 — A02 Cryptographic Failures:** <https://owasp.org/Top10/A02_2021-Cryptographic_Failures/>
- **OWASP Top 10:2021 — A03 Injection:** <https://owasp.org/Top10/A03_2021-Injection/>
- **OWASP Top 10:2021 — A04 Insecure Design:** <https://owasp.org/Top10/A04_2021-Insecure_Design/>
  *Why: A02–A04 are Lecture 2's three categories, in the official OWASP language.*
- **OWASP Top 10:2021 — A05 through A10** (one page per category, linked from the landing page above)
  *Why: Lecture 3's six categories, official definitions and real breach references for each.*

## Reference (keep in tabs)

- **OWASP Cheat Sheet Series — full index:** <https://cheatsheetseries.owasp.org/>
  *Why: the single best free, practitioner-written reference for "how do I actually fix this" across every category this week covers.*
- **OWASP Cheat Sheet — Authorization:** <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
- **OWASP Cheat Sheet — Password Storage:** <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- **OWASP Cheat Sheet — SQL Injection Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- **OWASP Cheat Sheet — Deserialization:** <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
- **OWASP Cheat Sheet — Server-Side Request Forgery Prevention:** <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- **OWASP Cheat Sheet — Logging:** <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- **MITRE — CWE (Common Weakness Enumeration), full list:** <https://cwe.mitre.org/data/index.html>
  *Why: the more granular taxonomy each Top 10 category groups — Problem 1 of the homework works directly from this.*
- **NIST National Vulnerability Database (NVD):** <https://nvd.nist.gov/vuln/search>
  *Why: search real, publicly disclosed CVEs by keyword or CVE ID — used in Problem 4 of the homework.*
- **Flask — Security Considerations (official docs):** <https://flask.palletsprojects.com/en/latest/security/>
  *Why: `SECRET_KEY`, session cookie flags, and debug-mode guidance straight from the framework's own maintainers.*
- **Werkzeug — the debugger, and why it's dangerous outside development:** <https://werkzeug.palletsprojects.com/en/latest/debug/>
  *Why: read the "PIN Security" section — the official explanation of exactly what Lecture 3, Section 1 demonstrated.*

## Tools used this week

- **`pip-audit` (PyPA official):** <https://github.com/pypa/pip-audit>
  *Why: the exact tool Lecture 3's A06 section runs against `crunch-notes`'s `requirements.txt`.*
- **`sqlite3` CLI** (ships with Python) — used for every findings-database query this week.
- **`curl`** — every demonstration and re-test this week is a `curl` command; if you're not yet comfortable with `-c`/`-b` (cookie jars), `-I` (headers only), and `-d`/`--data-urlencode` (form/query data), practice those four flags until they're automatic.

## Practice beyond `crunch-notes`

- **OWASP Juice Shop — full challenge list:** <https://owasp.org/www-project-juice-shop/>
  *Why: Challenge 1's target; the official project also publishes hint levels if you want a supported way to go further than this week's guidance.*
- **PortSwigger Web Security Academy** — free, browser-based labs covering every category this week touches, with guided and unguided tracks: <https://portswigger.net/web-security>
  *Why: the closest thing to an industry-standard free lab set for exactly this material; excellent next stop after this course.*
- **OWASP WebGoat:** <https://owasp.org/www-project-webgoat/>
  *Why: your Week 1 lab target's built-in lessons walk several of this week's categories with their own guided exercises.*

## Glossary

| Term | Definition |
|------|------------|
| **OWASP Top 10** | A ranked list of the ten most critical web application security risk categories, updated periodically from testing data and practitioner survey. |
| **CWE** | Common Weakness Enumeration — a granular taxonomy of specific vulnerability types; each Top 10 category groups several CWEs. |
| **CVE** | Common Vulnerabilities and Exposures — an identifier for one specific, publicly disclosed vulnerability in one specific piece of software. |
| **IDOR** | Insecure Direct Object Reference — using a client-supplied identifier to look up an object with no check that the requester is authorized for that specific object. |
| **Function-level access control** | Authorization enforced per *endpoint/function* (e.g., "admin only"), as distinct from per-object authorization (IDOR). |
| **Parameterized query** | A query where values are bound separately from the SQL text via placeholders, so the database itself can never interpret a value as executable SQL syntax. |
| **Salt** | A random value mixed into a password before hashing so identical passwords never produce identical hashes. |
| **Rainbow table** | A precomputed table mapping common password values to their hashes, used to reverse fast, unsalted hashes quickly. |
| **Deserialization** | Reconstructing a live object from a stored/transmitted byte representation; unsafe when the bytes are untrusted and the format (like Python's `pickle`) can encode executable behavior. |
| **SSRF** | Server-Side Request Forgery — tricking a server into making an HTTP request to a destination the attacker chose, often reaching internal-only services. |
| **Allowlist / blocklist** | An allowlist permits only explicitly approved values (deny by default); a blocklist rejects only explicitly known-bad values (allow by default) and is inherently incomplete. |
| **Findings database** | A structured, queryable store (this course: SQLite/Postgres) recording each security finding's demonstration, remediation, and re-test evidence. |

---

*Broken link? Open an issue or PR.*
