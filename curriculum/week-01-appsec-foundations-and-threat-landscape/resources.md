# Week 1 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Docker Desktop** (macOS/Windows) or **Docker Engine** (Linux) — runs every vulnerable target in this course's lab: <https://docs.docker.com/get-started/get-docker/>. Confirm with `docker --version` and `docker run hello-world`.
- **Python 3.10+** — for findings scripts and, later, tooling weeks: <https://www.python.org/downloads/>. `sqlite3` ships with Python; no separate install needed.
- **A text editor/IDE** — VS Code (free) is a solid default: <https://code.visualstudio.com/>.

## This week's lab targets (official sources only)

- **OWASP Juice Shop:** <https://owasp.org/www-project-juice-shop/> · Docker image: `bkimminich/juice-shop`.
- **DVWA (Damn Vulnerable Web Application):** <https://github.com/digininja/DVWA> · Docker image used here: `vulnerables/web-dvwa`. Default login after DB setup: `admin` / `password`.
- **OWASP WebGoat:** <https://owasp.org/www-project-webgoat/> · Docker image: `webgoat/webgoat`.

**Only ever pull vulnerable-app images from their official project pages or well-known, actively-maintained Docker Hub publishers** (as linked above). An unofficial "vulnerable app" from an unknown source could itself be malicious — verifying the source is part of keeping your own machine safe, not just the target.

## Required reading (this week's core)

- **OWASP — About the OWASP Foundation:** <https://owasp.org/about/>
  *Why: OWASP is the reference organization for nearly everything this course teaches from Week 3 onward — know what it is.*
- **OWASP — Risk Rating Methodology:** <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
  *Why: a more detailed version of this week's likelihood × impact model, from the source this course's simplified version is based on.*
- **NIST — Guide for Conducting Risk Assessments (SP 800-30), Chapter 2:** <https://csrc.nist.gov/pubs/sp/800/30/r1/final>
  *Why: the formal government-standard treatment of asset/threat/vulnerability/risk — read the definitions section, skim the rest.*
- **CISA — Security Tip: Understanding the CIA Triad:** <https://www.cisa.gov/news-events/news/security-tip-st04-013>
  *Why: a short, clear primer on confidentiality/integrity/availability from a government source.*
- **Docker — Networking overview:** <https://docs.docker.com/network/>
  *Why: understand what "bridge network" and "published port" actually mean before you trust your lab is isolated.*

## Reference (keep in tabs)

- **OWASP — Threat Modeling overview** (previews Week 2): <https://owasp.org/www-community/Threat_Modeling>
- **NIST — Glossary** (canonical definitions for asset/threat/vulnerability/risk and hundreds of other terms): <https://csrc.nist.gov/glossary>
- **SQLite — CREATE TABLE / generated columns:** <https://www.sqlite.org/gencol.html>
- **SQLite — Foreign Key Support** (why `PRAGMA foreign_keys = ON;` matters): <https://www.sqlite.org/foreignkeys.html>
- **Python — `sqlite3` module docs:** <https://docs.python.org/3/library/sqlite3.html>
- **U.S. DOJ — Computer Fraud and Abuse Act, prosecution guidance overview:** <https://www.justice.gov/jm/jm-9-48000-computer-fraud>
  *Why: understand the legal standard ("without authorization") that makes written authorization and defined scope non-optional in real security work.*
- **HackerOne — Disclosure Guidelines:** <https://www.hackerone.com/disclosure-guidelines>
  *Why: the professional-industry norm for scope and authorization that this week's Rules of Engagement challenge mirrors.*

## Practice beyond this week's lab

- **OWASP Juice Shop — official companion guide** (walkthroughs organized by OWASP Top 10 category, useful once you reach Week 3): <https://pwning.owasp-juice.shop/>
- **PortSwigger Web Security Academy** — free, browser-based labs covering the same vulnerability classes this course studies, with no local setup required: <https://portswigger.net/web-security>
  *Why: a strong second environment once your own lab is second nature, with guided labs per vulnerability class.*
- **OverTheWire — Natas** — free browser-based web-security wargame, good for building the "explore, don't assume" reconnaissance habit from Exercise 2: <https://overthewire.org/wargames/natas/>

## Deeper background (optional this week)

- **Verizon Data Breach Investigations Report (DBIR, annual, free):** <https://www.verizon.com/business/resources/reports/dbir/>
  *Why: real, current data behind Lecture 1's threat-landscape claims — read the executive summary at minimum.*
- **NIST — Secure Software Development Framework (SSDF, SP 800-218):** <https://csrc.nist.gov/pubs/sp/800/218/final>
  *Why: the federal framework behind "build security in across the SDLC," the theme Lecture 1's Section 5 previews and Week 10 formalizes.*

## Glossary

| Term | Definition |
|------|------------|
| **Asset** | Anything of value being protected (data, credentials, availability of a service, reputation). |
| **Threat** | A potential cause of harm — an actor or event that could cause damage to an asset. |
| **Vulnerability** | A weakness a threat could exploit to actually cause harm. |
| **Risk** | The combination of a threat exploiting a vulnerability against an asset; scored as likelihood × impact. |
| **CIA triad** | Confidentiality, integrity, availability — the three properties security protects. |
| **Attack surface** | The complete set of points where an untrusted actor could interact with a system. |
| **Trust boundary** | A point where data crosses between different levels of trust, requiring validation/authentication/authorization. |
| **Attacker/defender view** | This course's core habit: pairing every offensive concept with its detection and its fix. |
| **Isolated lab** | A test environment (VMs, containers) with no route to the internet or any real third-party system. |
| **Rules of Engagement (RoE)** | A written document defining who authorized testing, what's in and out of scope, permitted techniques, and the testing window. |
| **Findings store** | A structured, queryable record of security findings (SQL/Python) — never a spreadsheet. |
| **Risk register** | A structured list of scored risks, used to prioritize what gets fixed first. |

---

*Broken link? Open an issue or PR.*
