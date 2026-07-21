# Week 11 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Python 3.10+** and `pip` — ships with `sqlite3`; you already have both from earlier weeks.
- **`argon2-cffi`** (password hashing, from Week 4) and **Flask 3.x** — `pip install flask==3.0.3 argon2-cffi==23.1.0`.
- **`git`** — you're reading `PR #482` as a real unified diff (`git apply`), the way review tools present a pull request.
- **Semgrep** (for Challenge 2, from Week 8) — `pip install semgrep`. Confirm with `semgrep --version`.
- **A text editor with diff/patch syntax highlighting (optional but recommended)** — makes cold-reading `pr-482.diff` in Exercise 1 considerably easier to scan for `+`/`-` lines.

## Required reading (this week's core)

- **OWASP Code Review Guide** — the canonical, free, comprehensive guide this week's method is built on:
  <https://owasp.org/www-project-code-review-guide/>
  *Why: covers entry-point mapping, data-flow analysis, and control verification in far more depth than one week can, organized the same way this week's lectures are.*
- **Google Engineering Practices — "How to Do a Code Review"** and **"The CL author's guide to getting through code review"**:
  <https://google.github.io/eng-practices/review/reviewer/> · <https://google.github.io/eng-practices/review/developer/>
  *Why: the reviewer/author relationship this week's Lecture 3 addresses — written by engineers who review code for a living, at scale.*
- **CWE — Common Weakness Enumeration**, specifically the entries this week's findings cite:
  <https://cwe.mitre.org/data/definitions/89.html> (CWE-89, SQL Injection) ·
  <https://cwe.mitre.org/data/definitions/306.html> (CWE-306, Missing Authentication) ·
  <https://cwe.mitre.org/data/definitions/862.html> (CWE-862, Missing Authorization) ·
  <https://cwe.mitre.org/data/definitions/798.html> (CWE-798, Hard-coded Credentials) ·
  <https://cwe.mitre.org/data/definitions/327.html> (CWE-327, Broken/Risky Crypto Algorithm) ·
  <https://cwe.mitre.org/data/definitions/208.html> (CWE-208, Observable Timing Discrepancy)
  *Why: the standard vocabulary for naming a weakness precisely in a real report — cite the CWE, don't just describe the shape and hope the reader recognizes it.*
- **Python `hmac` module documentation:** <https://docs.python.org/3/library/hmac.html>
  *Why: `hmac.new(...)` and `hmac.compare_digest(...)` are the two calls this week's crypto fixes depend on — know their exact signatures cold.*

## Reference (keep in tabs)

- **OWASP Top 10 (2021)** — you already know these by name from Week 3; this week's findings map directly onto A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), and A07 (Identification and Authentication Failures):
  <https://owasp.org/Top10/>
- **OWASP Web Security Testing Guide — Authorization Testing chapter** (the manual-testing methodology behind Lecture 2's authz trace):
  <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/>
- **FIRST — CVSS v3.1 Specification** (a heavier severity framework, for when Lecture 3's lightweight rubric isn't granular enough for a real engagement):
  <https://www.first.org/cvss/v3.1/specification-document>
- **HackerOne — "How to Write a Great Vulnerability Report":** <https://www.hackerone.com/vulnerability-management/how-write-great-vulnerability-report>
  *Why: written for bug-bounty submissions, but the seven-field discipline (location, reproduction, impact, fix) is identical to what a good internal finding needs.*
- **Semgrep documentation — rule writing and registry:** <https://semgrep.dev/docs/>
  *Why: for Challenge 2, understanding what a Semgrep rule can and can't express in its own terms explains *why* certain findings are structurally hard for it to catch.*

## Practice beyond the lab app

- **OWASP Juice Shop** (from Week 1/3) — pick any five routes you haven't reviewed yet and run this week's four-step method against them cold, without the hints this week's materials gave you for `crunch-invoices`.
- **PortSwigger Web Security Academy — Access Control labs** (free): <https://portswigger.net/web-security/access-control>
  *Why: more authorization-gap patterns to taint-trace, beyond IDOR and the missing-role-check shape this week covered.*
- **Real open-source CVE writeups** — search any major CVE database (e.g., <https://nvd.nist.gov/>) for a CWE-89 or CWE-798 advisory in a project you recognize, and try writing your own seven-field finding for it, purely from the public advisory text, as practice translating someone else's disclosure into this week's format.

## Glossary

| Term | Definition |
|------|------------|
| **Entry point** | Any place attacker-influenced data can enter a program — routes, headers, files, queue messages, CLI args. |
| **Sink** | An operation dangerous enough that untrusted data (or an unchecked caller) reaching it causes a security problem. |
| **Taint tracing** | Following a value from source to sink, hop by hop, checking for a real sanitizer or control at each step. |
| **Source** | Where a taint trace begins — an entry point's specific value. |
| **Sanitizer** | An operation that genuinely neutralizes a specific danger for a specific sink (e.g., a parameterized query placeholder for SQL injection). Not every transformation is a real sanitizer for the sink you're worried about. |
| **Finding** | A documented, reproduced security defect with a location, description, reproduction, impact, severity, and recommended fix. |
| **False positive** | A reported finding that, on verification, isn't actually exploitable — the reason every finding in this course is confirmed before it's written up. |
| **CWE** | Common Weakness Enumeration — MITRE's standard catalog of weakness *types* (as opposed to CVE, which catalogs specific, named vulnerability *instances*). |
| **IDOR** | Insecure Direct Object Reference (Week 6) — an object accessed by an unchecked, client-supplied identifier. |
| **Homemade crypto** | A cryptographic construction assembled from primitives (hashes, string concatenation) instead of a vetted, purpose-built function (`hmac.new`, `argon2`, an AEAD cipher). |
| **Constant-time comparison** | A comparison whose running time doesn't depend on where two values first differ, closing a timing side-channel; `hmac.compare_digest` in Python. |
| **SAST** | Static Application Security Testing (Week 8) — scanning source code without running it, for known-bad syntactic patterns. |
| **`review_findings`** | This week's SQLite schema for tracking a finding from `open` through `fixed` to `retested_ok`. |

---

*Broken link? Open an issue or PR.*
