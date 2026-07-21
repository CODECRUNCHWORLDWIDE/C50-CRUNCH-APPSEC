# Week 12 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up. This week's list leans on standards and cheat sheets from every earlier week — the capstone doesn't introduce new tools, it asks you to apply the ones you already have.

## Install first (if not already, from Weeks 1–10)

- **Python 3.10+** — for Crunch Ledger and every findings/scan script this week: <https://www.python.org/downloads/>. `sqlite3` ships with Python.
- **Flask** — `pip install flask==3.0.3`: <https://flask.palletsprojects.com/>
- **`cryptography`** — `pip install cryptography`: <https://cryptography.io/>
- **Bandit** (SAST) — `pip install bandit`: <https://bandit.readthedocs.io/>
- **pip-audit** (SCA) — `pip install pip-audit`: <https://pypi.org/project/pip-audit/>
- **`requests`** (for the DAST probe script) — `pip install requests`: <https://requests.readthedocs.io/>

## Required reading (this week's core)

- **OWASP Threat Modeling Process:** <https://owasp.org/www-community/Threat_Modeling_Process>
  *Why: the formal process behind Lecture 1's scope-then-DFD-then-STRIDE-then-register sequence — read it end to end before your own threat model, not after.*
- **OWASP Risk Rating Methodology:** <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
  *Why: a more rigorous likelihood/impact scoring model than this week's simple grid — worth reading even though the capstone's register uses the simpler version, so you know what a fuller model looks like.*
- **OWASP Application Security Verification Standard (ASVS):** <https://owasp.org/www-project-application-security-verification-standard/>
  *Why: the industry-standard checklist Crunch Ledger's controls are a small, hands-on slice of — skim the Authentication, Access Control, and Cryptography chapters and notice how many map directly to this week's eleven fixes.*
- **OWASP Vulnerability Management Guide:** <https://owasp.org/www-project-vulnerability-management-guide/>
  *Why: the formal version of Lecture 3's triage-and-remediate loop — read the severity-scoring and remediation-tracking sections specifically.*
- **NIST SP 800-30 — Guide for Conducting Risk Assessments:** <https://csrc.nist.gov/pubs/sp/800/30/r1/final>
  *Why: the government-standard reference behind this week's risk register and the residual-risk sign-off Challenge 2 asks you to produce.*

## Reference (keep in tabs — one cheat sheet per fix category)

- **OWASP Password Storage Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html> — VULN #1's fix.
- **OWASP Session Management Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> — VULN #2's fix.
- **OWASP Query Parameterization Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html> — VULN #3's fix.
- **OWASP Access Control Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html> — VULN #4 and #5's fixes.
- **OWASP Secrets Management Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html> — VULN #6's fix.
- **OWASP Cryptographic Storage Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html> — VULN #7 and #8's fixes.
- **OWASP REST Security Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html> — VULN #9's fix.
- **OWASP Software Supply Chain Security Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security.html> — VULN #10's fix.
- **OWASP CI/CD Security Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html> — VULN #11's fix.

## Standards behind the tooling

- **CWE Top 25 Most Dangerous Software Weaknesses:** <https://cwe.mitre.org/top25/> — cross-reference every one of Crunch Ledger's eleven fixes against its CWE ID for your `SECURE-APPLICATION-REPORT.md`.
- **NIST SP 800-53 — Security and Privacy Controls:** <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final> — the formal control catalog behind "security built in" as an SDLC discipline, not a scanning afterthought.
- **SLSA (Supply-chain Levels for Software Artifacts):** <https://slsa.dev/> — the maturity model Lecture 2's CI/CD gate is a first, small step toward.

## Practice beyond this week's lab

- **OWASP Juice Shop** — a full deliberately-vulnerable app, free and self-hosted, with a broader vulnerability set than any single week's target: <https://pwning.owasp-juice.shop/>
- **OWASP DevSecOps Guideline** — a practical walkthrough of wiring SAST/DAST/SCA into a real pipeline, the production-scale version of this week's `ci_pipeline.yml`: <https://owasp.org/www-project-devsecops-guideline/>
- **PortSwigger Web Security Academy** — free, browser-based labs across every vulnerability class this course covered, a strong ongoing practice ground after the capstone: <https://portswigger.net/web-security>

## Glossary

| Term | Definition |
|---|---|
| **STRIDE** | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — a per-element threat-modeling checklist. |
| **DFD** | Data-flow diagram — processes, data stores, external entities, and flows between them, with trust boundaries marked. |
| **Trust boundary** | A point in a DFD where privilege or trust level changes; STRIDE threats concentrate here. |
| **Risk register** | A table of identified risks with likelihood, impact, computed priority, and status — the artifact that drives what gets fixed first. |
| **SAST** | Static Application Security Testing — analyzing source code without running it. |
| **DAST** | Dynamic Application Security Testing — probing a running application from the outside, like an external caller. |
| **SCA** | Software Composition Analysis — scanning dependencies for known-vulnerable versions. |
| **Findings triage** | Merging findings from multiple sources into one prioritized backlog, ordered by real-world severity, not by source. |
| **Business-logic flaw** | A design gap where every individual technical check passes but the overall policy doesn't make sense — invisible to scanners, found only by reasoning about intent. |
| **Residual risk** | Risk that remains after remediation, explicitly identified, sized, and owned rather than left unexamined. |
| **Design defense** | A structured review where the builder justifies design decisions, fixes, and accepted risks to a reviewer who wasn't part of the build. |

---

*Broken link? Open an issue or PR.*
