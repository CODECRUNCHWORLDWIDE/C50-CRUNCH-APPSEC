# Week 8 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Semgrep (SAST):** `pip install semgrep` — <https://semgrep.dev/docs/getting-started/>. Confirm with `semgrep --version`.
- **OWASP ZAP (DAST):** Docker image, no local install needed beyond Docker itself — <https://www.zaproxy.org/download/>. Confirm with `docker pull zaproxy/zap-stable`.
- **Trivy (SCA):** <https://trivy.dev/latest/getting-started/installation/> — `brew install trivy` on macOS, or the official install script on Linux. Confirm with `trivy --version`.
- **OSV-Scanner (SCA alternative):** <https://google.github.io/osv-scanner/installation/> — optional, used for Exercise 1's stretch goal and Challenge 2's tool comparison.

## This week's targets (official sources only)

- **OWASP Juice Shop — source repository** (this week's SAST/SCA analysis target): <https://github.com/juice-shop/juice-shop>
- **OWASP Juice Shop — running instance** (this week's DAST target, from your Week 1 lab): `docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop`

**Only ever clone or pull from official project pages** (as linked above). This week you're both reading source (SAST) and scanning dependencies (SCA) from a real, sizable codebase — verifying you're working from the genuine, official repository matters as much here as verifying your Docker image source did back in Week 1.

## Required reading (this week's core)

- **Semgrep — Rule writing documentation:** <https://semgrep.dev/docs/writing-rules/overview>
  *Why: this is the primary reference for everything Lecture 1, Section 5 and Challenge 1 ask you to do.*
- **Semgrep — Taint tracking mode:** <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode>
  *Why: needed if your Challenge 1 or Homework Problem 3 rule involves multi-hop data flow rather than a single-line pattern.*
- **OWASP ZAP — Getting Started guide:** <https://www.zaproxy.org/getting-started/>
  *Why: the official walkthrough behind Lecture 2 and Exercise 2's baseline/full-scan commands.*
- **OWASP ZAP — Docker automation packages:** <https://www.zaproxy.org/docs/docker/>
  *Why: the exact reference for the `zap-baseline.py`/`zap-full-scan.py` flags used throughout this week.*
- **Trivy — Vulnerability scanning:** <https://trivy.dev/latest/docs/scanner/vulnerability/>
  *Why: the primary reference for Lecture 3's SCA scan and Exercise 3's Trivy loader script.*
- **OSV — Open Source Vulnerability schema:** <https://ossf.github.io/osv-schema/>
  *Why: understand the data format underlying both Trivy's and OSV-Scanner's vulnerability matching.*

## Reference (keep in tabs)

- **OWASP — Source Code Analysis Tools** (a broader landscape of SAST tools beyond Semgrep): <https://owasp.org/www-community/Source_Code_Analysis_Tools>
- **MITRE — Common Weakness Enumeration (CWE)** (the taxonomy behind rule `metadata.cwe` tags): <https://cwe.mitre.org/>
- **FIRST — Common Vulnerability Scoring System (CVSS) specification** (how the severity scores in CVE/advisory databases are computed): <https://www.first.org/cvss/>
- **GitHub Security Advisories database:** <https://github.com/advisories>
- **NIST National Vulnerability Database (NVD):** <https://nvd.nist.gov/>
- **CISA — Known Exploited Vulnerabilities (KEV) Catalog** (a real-world exploitation signal worth cross-referencing during SCA triage): <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- **SQLite — `ALTER TABLE` documentation** (needed for Challenge 2's `duplicate_of` column): <https://www.sqlite.org/lang_altertable.html>
- **Python — `sqlite3` module docs:** <https://docs.python.org/3/library/sqlite3.html>

## Practice beyond this week's lab

- **OWASP Juice Shop — official companion guide**, organized by OWASP Top 10 category (useful for cross-referencing what your scanners find against known, documented Juice Shop vulnerabilities): <https://pwning.owasp-juice.shop/>
- **PortSwigger Web Security Academy** — free labs where you can practice reading DAST-style alerts against guided, purpose-built vulnerable scenarios: <https://portswigger.net/web-security>
- **OWASP Benchmark Project** — a purpose-built test suite specifically designed to measure SAST/DAST tool accuracy (true-positive/false-positive rates), useful once you want to compare tools rigorously rather than anecdotally: <https://owasp.org/www-project-benchmark/>

## Deeper background (optional this week)

- **NIST — SP 800-218 Secure Software Development Framework (SSDF)** — situates SAST/DAST/SCA within a broader secure-development lifecycle, previewing Week 10: <https://csrc.nist.gov/pubs/sp/800/218/final>
- **OWASP — DevSecOps Guideline** (how scanning fits into a CI/CD pipeline, previewing Week 10): <https://owasp.org/www-project-devsecops-guideline/>

## Glossary

| Term | Definition |
|------|------------|
| **SAST** | Static Application Security Testing — analyzes source code without executing it, using AST/data-flow modeling and pattern-matching. |
| **DAST** | Dynamic Application Security Testing — probes a running application over HTTP without visibility into its source. |
| **SCA** | Software Composition Analysis — scans dependency manifests against vulnerability databases for known-CVE library versions. |
| **Taint tracking** | Following a value from an untrusted source through a program to see if it reaches a dangerous sink without passing through a sanitizer. |
| **Source (SAST)** | Any point where untrusted data enters a program (e.g., a query parameter, a form field). |
| **Sink (SAST)** | A dangerous operation (e.g., a raw SQL query, a shell command) that should never receive unsanitized tainted data. |
| **Spider** | A DAST crawler that discovers URLs, forms, and parameters by walking the application like a user would. |
| **Passive scan** | DAST analysis of traffic already observed, sending no additional requests. |
| **Active scan** | DAST analysis that sends crafted, potentially malicious payloads to discovered inputs to provoke a vulnerable response. |
| **Reachability problem** | When SCA matches a real CVE to an installed library version, but the vulnerable function is never actually called in the application's code path. |
| **Reconciliation** | Merging findings from multiple scanners that describe the same underlying weakness, while keeping genuinely distinct findings separate. |
| **True positive** | A finding confirmed, with evidence, to represent a real vulnerability. |
| **False positive** | A finding dismissed with a specific, written justification for why it does not represent a real risk. |
| **Findings backlog** | A structured, queryable, risk-ranked list of triaged findings — SQL/Python, never a spreadsheet. |

---

*Broken link? Open an issue or PR.*
