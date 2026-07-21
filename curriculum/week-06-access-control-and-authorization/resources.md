# Week 6 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first (if not already, from Week 1/3/4)

- **Python 3.10+** — for `crunch-helpdesk` and every findings/test script this week: <https://www.python.org/downloads/>. `sqlite3` ships with Python; no separate install needed.
- **Flask 3.x** — `pip install flask==3.0.3`: <https://flask.palletsprojects.com/>
- **`requests`** (for the test-matrix and tenant-fuzz scripts) — `pip install requests`: <https://requests.readthedocs.io/>

## Required reading (this week's core)

- **OWASP Top 10 (2021) — A01 Broken Access Control:** <https://owasp.org/Top10/A01_2021-Broken_Access_Control/>
  *Why: the category this entire week is the deep-dive on; read it end to end, you'll recognize every sub-pattern from this week's lectures.*
- **OWASP — Access Control Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html>
  *Why: the industry-standard checklist this week's routes are built to satisfy — deny by default, enforce server-side, fail securely.*
- **OWASP — Authorization Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
  *Why: the "fail securely" and "enforce at every layer" sections map directly to Lecture 3's deny-by-default design.*
- **OWASP — Testing for Insecure Direct Object References:** <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References>
  *Why: the formal testing methodology behind Lecture 2 and Exercise 1's demonstrate-and-fix loop.*
- **NIST SP 800-162 — Guide to Attribute Based Access Control (ABAC):** <https://csrc.nist.gov/pubs/sp/800/162/final>
  *Why: the reference model behind Lecture 1's ABAC section — read the executive summary and the subject/resource/action/environment attribute categories at minimum.*
- **NIST — Role Based Access Control (RBAC) project overview:** <https://csrc.nist.gov/projects/role-based-access-control>
  *Why: the formal government standard behind Lecture 1's RBAC section, including the role-explosion failure mode this week names explicitly.*

## Reference (keep in tabs)

- **CWE-639 — Authorization Bypass Through User-Controlled Key** (the formal name for IDOR): <https://cwe.mitre.org/data/definitions/639.html>
- **CWE-862 — Missing Authorization:** <https://cwe.mitre.org/data/definitions/862.html>
- **CWE-863 — Incorrect Authorization:** <https://cwe.mitre.org/data/definitions/863.html>
- **CWE-284 — Improper Access Control** (parent category): <https://cwe.mitre.org/data/definitions/284.html>
- **PortSwigger Web Security Academy — Access control vulnerabilities:** <https://portswigger.net/web-security/access-control>
  *Why: free, browser-based labs on IDOR and horizontal/vertical escalation, a strong second environment once your own lab feels routine.*
- **Flask — `before_request` documentation** (used for this week's deny-by-default hook): <https://flask.palletsprojects.com/en/latest/api/#flask.Flask.before_request>
- **Python — `sqlite3` module docs:** <https://docs.python.org/3/library/sqlite3.html>
- **`requests` — Session objects** (used by the test-matrix runner and tenant fuzzer to persist login cookies per user): <https://requests.readthedocs.io/en/latest/user/advanced/#session-objects>

## Practice beyond this week's lab

- **PortSwigger — IDOR labs** (guided, free, no local setup): <https://portswigger.net/web-security/access-control/idor>
- **PortSwigger — Privilege escalation labs:** <https://portswigger.net/web-security/access-control#privilege-escalation>
- **OWASP Juice Shop** (from your Week 1 lab) — its "Broken Access Control" challenge category is a strong next target for the exact patterns this week covered, once `crunch-helpdesk` is second nature: <https://pwning.owasp-juice.shop/>

## Deeper background (optional this week)

- **Verizon DBIR (annual, free)** — Broken Access Control and similar categories consistently rank among the top breach patterns in real incident data; read the current year's web-application-attacks section: <https://www.verizon.com/business/resources/reports/dbir/>
- **NIST — Guide to Attribute Based Access Control, Section 3 (Core ABAC Functional Components)** — the formal policy-decision-point / policy-enforcement-point architecture this week's `require_permission` decorator and object-check functions are a simplified version of: <https://csrc.nist.gov/pubs/sp/800/162/final>

## Glossary

| Term | Definition |
|---|---|
| **Authentication (authn)** | Verifying identity — who is making this request. |
| **Authorization (authz)** | Verifying permission — what this specific, identified requester is allowed to do. |
| **RBAC** | Role-Based Access Control — permissions granted to roles, users assigned to roles. |
| **ABAC** | Attribute-Based Access Control — access decided by evaluating attributes of the subject, resource, action, and environment. |
| **Role explosion** | The RBAC failure mode where per-object or per-attribute rules get modeled as new roles instead of object-level checks, growing the role table unmanageably. |
| **IDOR** | Insecure Direct Object Reference — using a client-supplied identifier to fetch/modify an object with no check that the requester may access that specific object. |
| **Horizontal privilege escalation** | Accessing another identity's data or acting as them, at the same privilege level. |
| **Vertical privilege escalation** | Reaching a higher privilege level (role/permission) than assigned. |
| **Deny-by-default** | A design where every route must explicitly declare what's permitted; anything undeclared is blocked, failing safe rather than open. |
| **Multi-tenancy** | An architecture where multiple customers ("tenants") share one deployment; every tenant's data must be isolated from every other's regardless of role. |
| **Tenant floor check** | The mandatory, absolute check that a resource belongs to the requester's own tenant — must run before, and cannot be overridden by, any role or ownership match. |
| **Authorization test matrix** | A data-driven table of (role, resource, action, expected outcome) rows, run systematically to prove — not sample — authorization coverage. |

---

*Broken link? Open an issue or PR.*
