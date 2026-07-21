# C50 · Crunch AppSec

> A free, open-source 12-week course on shipping secure software: OWASP Top 10, threat modeling, secure coding, SAST/DAST, and a secure SDLC — practiced against intentionally-vulnerable apps.

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)
[![PostgreSQL · Python](https://img.shields.io/badge/stack-PostgreSQL_·_Python-2463EB.svg)](#stack)
[![Built in the open](https://img.shields.io/badge/built-in%20the%20open-2463EB.svg)](https://github.com/CODECRUNCHWORLDWIDE)

C50 is an application-security course that takes you from "what is an attacker's mindset?" to threat-modeling a system, finding real vulnerability classes, and fixing them at the source with secure code. It builds on the web and backend courses — [C15 Crunch Pro Web Frontend](../C15-CRUNCH-PRO-WEB-FRONTEND/), [C16 Crunch Pro Web Backend](../C16-CRUNCH-PRO-WEB-BACKEND/), and [C33 Crunch SQL](../C33-CRUNCH-SQL/) — and makes you the person on the team who ships software that holds up.

> **Ethics & legality — read first.** Everything here is **authorized, legal, defensive** security work performed **only in isolated lab environments you own** — deliberately-vulnerable VMs, sandboxes, and CTF targets. You will **never** be pointed at a real third-party system. Every offensive technique is taught **so you can detect and defend against it**. Malware analysis and reverse engineering run **only inside an isolated, no-network sandbox**. Written authorization, defined scope, and the law govern every exercise — no exceptions.

---

## Pathway summary

- **Full-time:** 12 weeks · ~28 hrs/week · ~336 hours
- **Working-engineer pace:** 6 months · ~14 hrs/week
- **Evening pace:** 12 months · ~7 hrs/week

See [`SYLLABUS.md`](SYLLABUS.md).

---

## What you will be able to do at the end of 12 weeks

- **Think like both sides:** hold the attacker/defender view of a system and translate an attack into a concrete detection and a source-level fix.
- **Model threats:** run a STRIDE threat-modeling session on a real design, produce a data-flow diagram, and rank mitigations by risk.
- **Know the OWASP Top 10 cold:** recognize each risk class in code, demonstrate it in a lab target, and remediate it — with broken access control, injection, and cryptographic failures front and center.
- **Get auth right:** implement password storage, MFA, and session management that resist credential stuffing, fixation, and hijacking.
- **Defeat injection:** treat all input as hostile, validate and encode correctly, and use **parameterized SQL** as the non-negotiable defense.
- **Enforce access control:** design authorization that fails closed — RBAC/ABAC, deny-by-default, and no IDOR.
- **Handle secrets and crypto safely:** manage keys and secrets, and use vetted primitives for hashing, encryption, and signing without rolling your own.
- **Automate the hunt:** wire SAST, DAST, and SCA into a pipeline and triage findings without drowning in false positives.
- **Secure the supply chain and the SDLC:** lock down APIs, dependencies, and CI/CD, and run a real secure code review.
- **Ship a secure app:** threat-model, build, test, and defend a small application end to end — the capstone.

---

## Curriculum (12 weeks)

| Week | Topic | You leave able to… |
|------|-------|--------------------|
| 1 | [AppSec foundations & the attacker/defender view](curriculum/week-01-appsec-foundations-and-threat-landscape/) | Set up an isolated lab and reason about assets, threats, and risk. |
| 2 | [Threat modeling with STRIDE](curriculum/week-02-threat-modeling-with-stride/) | Run a STRIDE session and produce a ranked mitigation list. |
| 3 | [The OWASP Top 10 in depth](curriculum/week-03-owasp-top-10-deep-dive/) | Map each Top 10 risk to code, a lab demo, and a fix. |
| 4 | [Authentication & session security](curriculum/week-04-authentication-and-session-security/) | Store passwords, add MFA, and manage sessions safely. |
| 5 | [Injection & input validation](curriculum/week-05-injection-and-input-validation/) | Kill injection with validation, encoding, and parameterized SQL. |
| 6 | [Access control & authorization](curriculum/week-06-access-control-and-authorization/) | Build deny-by-default authz with no IDOR or privilege escalation. |
| 7 | [Secrets management & applied crypto](curriculum/week-07-secrets-management-and-applied-crypto/) | Manage secrets and use crypto primitives correctly. |
| 8 | [SAST, DAST & SCA tooling](curriculum/week-08-sast-dast-and-sca-tooling/) | Wire automated scanners into a pipeline and triage findings. |
| 9 | [API & supply-chain security](curriculum/week-09-api-and-supply-chain-security/) | Secure APIs and defend the dependency supply chain. |
| 10 | [Secure SDLC & CI/CD security](curriculum/week-10-secure-sdlc-and-ci-cd-security/) | Bake security into the SDLC and harden the CI/CD pipeline. |
| 11 | [Secure code review](curriculum/week-11-secure-code-review/) | Review code for vulnerabilities and write actionable findings. |
| 12 | [Capstone — secure application](curriculum/week-12-capstone-secure-application/) | Threat-model, build, test, and defend a small app end to end. |

---

## How to navigate a week

Every week folder holds the same structure:

- **`README.md`** — the week overview + how the pieces fit + the week's goal.
- **`lecture-notes/`** — 3 lectures (~2 hrs each), the conceptual core.
- **`exercises/`** — 3 short, guided reps against a lab target.
- **`challenges/`** — 2 open-ended problems with no single right answer.
- **`mini-project/`** — one build that ties the week together.
- **`homework.md`**, **`quiz.md`**, **`resources.md`** — practice, self-check, and further reading.

---

## Stack

An **isolated, no-network lab** you own — deliberately-vulnerable apps (OWASP Juice Shop, DVWA, WebGoat), local VMs/containers, and CTF targets. **Python** for tooling, exploit-and-fix scripts, and analysis; **PostgreSQL/SQLite** for any logs, findings, and telemetry the course stores or queries — never a spreadsheet as a database. Open-source scanners (Semgrep, OWASP ZAP, Trivy/OSV) round out the toolchain. Everything is free and runs on macOS, Linux, and Windows.

---

*Part of the Code Crunch Worldwide open curriculum · GPL-3.0 · [Browse all courses](https://codecrunchglobal.vercel.app/courses)*
