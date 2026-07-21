# Week 9 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific category or question comes up.

## Install first (if you haven't already)

- **Python 3.10+** — `crunch-tasks-api` and every script this week runs on it: <https://www.python.org/downloads/>
- **`pip-audit`** — this week's SBOM generator and vulnerability scanner: `pip install pip-audit`
- **`pip-tools`** — hash-pinned lockfiles for Exercise 3/Lecture 3: `pip install pip-tools`
- **`Flask-Limiter`** — the rate limiter used in Lecture 2/Challenge 1: `pip install flask-limiter`
- **`build`** — needed to package the local demo packages in Lecture 3/Challenge 2: `pip install build`

## Required reading (this week's core)

- **OWASP API Security Top 10 (2023) — full list, landing page:** <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
  *Why: the canonical, current version of the list Lecture 1 is built on. Read the one-paragraph overview for each of the ten before Lecture 1.*
- **OWASP API Security — API1:2023 Broken Object Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- **OWASP API Security — API3:2023 Broken Object Property Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
  *Why: the official definition covering both mass assignment and excessive data exposure, Lecture 1's pair.*
- **OWASP API Security — API4:2023 Unrestricted Resource Consumption:** <https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/>
- **OWASP API Security — API5:2023 Broken Function Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
- **CycloneDX — official specification, "Overview" section:** <https://cyclonedx.org/specification/overview/>
  *Why: the SBOM format Exercise 3 generates and Lecture 3 explains.*

## Reference (keep in tabs)

- **OWASP API Security Top 10 — full 2023 edition (all ten categories):** <https://owasp.org/API-Security/editions/2023/en/0x00-header/>
- **OWASP Cheat Sheet — REST Security:** <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- **OWASP Cheat Sheet — Mass Assignment:** <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
- **OWASP Cheat Sheet — JSON Web Token (JWT) for Java** (concepts apply beyond Java)**:** <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html>
- **RFC 6749 — The OAuth 2.0 Authorization Framework:** <https://www.rfc-editor.org/rfc/rfc6749>
  *Why: the actual standard behind Lecture 2's OAuth 2.0 overview, for when you need the delegated-authorization pattern for real.*
- **`marshmallow` — schema validation for Python:** <https://marshmallow.readthedocs.io/>
- **`Flask-Limiter` — official docs:** <https://flask-limiter.readthedocs.io/>
- **`pip-tools` — hash-pinned lockfiles:** <https://pip-tools.readthedocs.io/>
- **Sigstore — keyless code signing and transparency logs:** <https://www.sigstore.dev/>
- **PEP 740 — Index support for digital attestations:** <https://peps.python.org/pep-0740/>
- **NIST SP 800-218 — Secure Software Development Framework:** <https://csrc.nist.gov/pubs/sp/800/218/final>

## Tools used this week

- **`pip-audit` (PyPA official):** <https://github.com/pypa/pip-audit>
  *Why: generates this week's CycloneDX SBOM and scans it against the same Python Packaging Advisory Database used in Week 8.*
- **`pip-compile` (from `pip-tools`):** generates a fully hash-pinned lockfile from a loose `requirements.in` — used in Lecture 3 and the mini-project.
- **`curl`** — every API demonstration and re-test this week is a `curl` command; if `-H` (custom headers, for `Authorization: Bearer ...`), `-X` (HTTP method), and `-d`/`--data-urlencode` aren't yet automatic, practice them until they are.
- **`sqlite3` CLI** (ships with Python) — used for every findings-database query this week.

## Practice beyond `crunch-tasks-api`

- **OWASP crAPI ("completely ridiculous API")** — a free, purpose-built, deliberately vulnerable API covering the full API Top 10, designed for exactly this kind of practice: <https://github.com/OWASP/crAPI>
  *Why: the natural next stop after this week — a larger, more realistic API with the same category of flaws, running in your own isolated lab.*
- **PortSwigger Web Security Academy — API testing labs:** <https://portswigger.net/web-security/api-testing>
  *Why: free, browser-based labs specifically on API authentication and authorization flaws.*
- **HackerOne Hacktivity — disclosed API reports:** <https://hackerone.com/hacktivity>
  *Why: real, publicly disclosed API vulnerability writeups — read for pattern recognition (Homework Problem 3), never as a target.*

## Glossary

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object-Level Authorization — an API endpoint fetches or modifies an object by client-supplied ID with no check that the caller is authorized for that specific object; the API-world name for IDOR. |
| **BFLA** | Broken Function-Level Authorization — an API endpoint performs a privileged action with no check that the caller's role permits calling that function at all. |
| **Mass assignment** | An endpoint writes every field present in a client's request body to the underlying object, with no allowlist restricting which fields the client may actually set. |
| **Excessive data exposure** | An endpoint returns more of an object's fields than the client legitimately needs, often by serializing the raw database row directly. |
| **Rate limiting** | Restricting how many requests a given caller (by IP, token, or account) may make in a given time window, typically via a token-bucket algorithm. |
| **API key** | A static, opaque secret string used to authenticate API requests; simple, revocable by database deletion, requires a lookup on every request. |
| **JWT (JSON Web Token)** | A signed, self-contained token carrying claims (e.g., user ID, role, expiry); verifiable without a database lookup, but harder to revoke early. |
| **OAuth 2.0** | A standard for delegated, scoped authorization — letting a third party act on a user's behalf without ever seeing the user's credentials. |
| **Dependency confusion** | An attack exploiting a package name that exists both privately/internally and publicly, tricking a resolver into installing the attacker's public package instead of the intended internal one. |
| **Typosquatting** | Publishing a malicious package under a name that's a near-miss (transposition, misspelling) of a popular legitimate package, betting on developer typos. |
| **Lockfile** | A file recording the *exact* resolved version (and, ideally, cryptographic hash) of every dependency, direct and transitive, so every install is reproducible and verifiable. |
| **SBOM** | Software Bill of Materials — a structured, machine-readable inventory of every component in a piece of software, in a standard format like CycloneDX or SPDX. |
| **`purl` (package URL)** | A standard identifier format (`pkg:ecosystem/name@version`) used in SBOMs and advisory databases to unambiguously reference a specific package and version. |
| **Provenance** | Cryptographic proof that a published artifact was actually built from the source code and pipeline it claims, by the entity it claims — e.g., via Sigstore or a registry-native attestation. |

---

*Broken link? Open an issue or PR.*
