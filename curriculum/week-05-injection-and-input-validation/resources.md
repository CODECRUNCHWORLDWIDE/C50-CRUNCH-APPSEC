# Week 5 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Python 3.10+** — <https://www.python.org/downloads/>. `sqlite3` ships with Python; no separate install.
- **Flask** — `pip install flask` — runs this week's Crunch Notes lab app: <https://flask.palletsprojects.com/>.
- **`requests`** — `pip install requests` — for scripted payload verification: <https://requests.readthedocs.io/>.
- **A text editor/IDE** — VS Code (free) is a solid default: <https://code.visualstudio.com/>.

## This week's lab app

- **Crunch Notes** — full source is in the [week README](./README.md). It's your own file — there's no external download; you type/paste it once and own the copy you break and fix.

## Required reading (this week's core)

- **OWASP — Injection Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html>
  *Why: the overarching pattern behind Lecture 1 — same source used for the "universal shape" framing.*
- **OWASP — SQL Injection Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
  *Why: the canonical reference for Lecture 2's parameterization argument, with more language/framework examples than this week covers.*
- **OWASP — Cross Site Scripting Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
  *Why: the context-by-context encoding table Lecture 3 Section 4 is based on — keep this one bookmarked long after this course ends.*
- **OWASP — DOM based XSS Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
  *Why: the sources/sinks framing behind Lecture 3 Section 5.*
- **MDN — Content Security Policy (CSP):** <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
  *Why: full directive reference for Homework Problem 3.*
- **Python — `sqlite3`: placeholders:** <https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders>
  *Why: the exact API this week's parameterized-query examples use.*

## Reference (keep in tabs)

- **OWASP — OS Command Injection Defense Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>
- **OWASP — LDAP Injection Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
- **PortSwigger — Server-side template injection:** <https://portswigger.net/web-security/server-side-template-injection>
- **Flask/Jinja2 — Autoescaping:** <https://jinja.palletsprojects.com/en/stable/templates/#html-escaping>
- **SQLAlchemy — `text()` and bound parameters:** <https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text>
- **Python — `subprocess`: list-form arguments vs. shell:** <https://docs.python.org/3/library/subprocess.html#security-considerations>
- **Python — `ipaddress` module:** <https://docs.python.org/3/library/ipaddress.html>
- **`bleach` (Python HTML sanitizer):** <https://bleach.readthedocs.io/>
- **DOMPurify (JS HTML sanitizer):** <https://github.com/cure53/DOMPurify>
- **MDN — `Set-Cookie`: `HttpOnly`/`Secure`/`SameSite`:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>

## Practice beyond this week's lab

- **PortSwigger Web Security Academy — SQL injection labs:** <https://portswigger.net/web-security/sql-injection>
  *Why: free, browser-based, guided labs covering boolean-blind and time-based SQLi against realistic targets, with no local setup — the natural next step after Challenge 2.*
- **PortSwigger Web Security Academy — Cross-site scripting labs:** <https://portswigger.net/web-security/cross-site-scripting>
- **OWASP Juice Shop** (from Week 1's lab) — has its own SQL injection and XSS challenges tracked on its scoreboard; revisit it now that you know what to look for: <https://owasp.org/www-project-juice-shop/>

## Deeper background (optional this week)

- **MITRE CWE-89 — SQL Injection:** <https://cwe.mitre.org/data/definitions/89.html>
- **MITRE CWE-78 — OS Command Injection:** <https://cwe.mitre.org/data/definitions/78.html>
- **MITRE CWE-79 — Cross-site Scripting:** <https://cwe.mitre.org/data/definitions/79.html>
- **CISA/NSA — joint guidance on eliminating SQL injection (2025):** <https://www.cisa.gov/resources-tools/resources/secure-by-design-alert-eliminating-sql-injection-vulnerabilities-software>
  *Why: government-level framing of "parameterized queries are the fix, not one option among several" — the same claim this week makes, from a different authority.*

## Glossary

| Term | Definition |
|------|------------|
| **Injection** | Untrusted data crossing into an interpreter (SQL, shell, LDAP, template engine) without being kept separate from instructions. |
| **Parameterized query / prepared statement** | A query where structure and data are sent to the database separately, so data is bound in as literal values after parsing, never re-parsed as syntax. |
| **Blocklist** | A defense that rejects known-bad patterns; fails because it can't anticipate every bypass. |
| **Allowlist** | A defense that accepts only known-good patterns, rejecting everything else by default; the correct model for input validation. |
| **SSTI (server-side template injection)** | Passing untrusted data as template *text* (re-parsed by the template engine) rather than as a *value* filled into a fixed template. |
| **Reflected XSS** | Untrusted data echoed back unencoded in the same response, requiring the victim to submit/click the crafted request. |
| **Stored XSS** | Untrusted data saved and later served unencoded to other requests/users. |
| **DOM-based XSS** | Untrusted client-side data (URL, hash) written into the page via a JS sink (`innerHTML`, etc.) with no server involvement. |
| **Output encoding** | Transforming data for the specific context it lands in (HTML body, attribute, JS string, URL) so it's treated as inert text, not markup/code. |
| **CSP (Content Security Policy)** | A browser-enforced HTTP header restricting script/resource sources; defense-in-depth, not a substitute for output encoding. |
| **Boolean-blind injection** | Inferring true/false one bit at a time from which of two fixed responses an injected condition produces. |
| **Time-based blind injection** | Inferring true/false from response latency when an injected conditional delay executes. |
| **Payload library** | A stored, queryable table of injection payloads used to verify defenses hold — never a spreadsheet. |

---

*Broken link? Open an issue or PR.*
