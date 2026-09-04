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

## Standards & equivalency

> C50 stands in for a university course in secure software development.

**University equivalent.** Secure Software Development — `CIS 4365`, `CS 4235`, `CSC 515`. Coverage: full — every outcome of that course is mapped to a week below, and every one of those weeks assigns work on it.

C50 carries no credit, no transcript entry, no accreditation and no proctored exam. The equivalence is one of **content and skill**: everything an accredited section of that course teaches, taught here at the same depth or deeper, and assessed. What a registrar records is not something an open repository can give you.

| University outcome | Where this course teaches it | Depth |
| --- | --- | --- |
| Reason about assets, threats, vulnerabilities and risk, and explain the security properties — confidentiality, integrity, availability — a software system has to hold | [Week 01](curriculum/week-01-appsec-foundations-and-threat-landscape/) | same |
| Construct a threat model of a design: a data-flow diagram, its trust boundaries, a structured threat taxonomy, and a ranked set of mitigations | [Week 02](curriculum/week-02-threat-modeling-with-stride/) | same |
| Identify, classify and remediate the principal vulnerability classes found in production software | [Week 03](curriculum/week-03-owasp-top-10-deep-dive/) | deeper |
| Implement authentication and session management that resists the known attacks on credentials and sessions | [Week 04](curriculum/week-04-authentication-and-session-security/) | deeper |
| Explain how injection arises across interpreters, and defeat it with input validation, output encoding and safe APIs | [Week 05](curriculum/week-05-injection-and-input-validation/) | deeper |
| Design and enforce an access-control policy inside an application, and test that the policy actually holds | [Week 06](curriculum/week-06-access-control-and-authorization/) | same |
| Apply cryptographic primitives correctly and manage keys and secrets across an application's lifecycle | [Week 07](curriculum/week-07-secrets-management-and-applied-crypto/) | same |
| Apply static, dynamic and dependency analysis to a codebase, and interpret and triage what comes back | [Week 08](curriculum/week-08-sast-dast-and-sca-tooling/) | deeper |
| Secure a service interface and the software supply chain it depends on | [Week 09](curriculum/week-09-api-and-supply-chain-security/) | deeper |
| Place security activities across every phase of the development lifecycle, including automated verification in the build pipeline | [Week 10](curriculum/week-10-secure-sdlc-and-ci-cd-security/) | deeper |
| Conduct a secure code review and report findings a developer can act on | [Week 11](curriculum/week-11-secure-code-review/) | deeper |
| Carry a secure-development project end to end and defend the design under questioning | [Week 12](curriculum/week-12-capstone-secure-application/) | deeper |

Every row points at a week that **assigns work** on the outcome — three exercises, two challenges, a mini-project, homework and a quiz — not a week that merely mentions it. All thirty-six exercises close with a `Done when…` list and a `Submission` line naming where the work goes.

**The industry bar.** What an employer expects of somebody paid to keep an application secure, and where this course makes the learner do it.

| What the job expects | Where this course does it |
| --- | --- |
| Written authorization and a defined scope exist before any testing starts | [`curriculum/week-01-appsec-foundations-and-threat-landscape/challenges/challenge-01-write-a-rules-of-engagement.md`](curriculum/week-01-appsec-foundations-and-threat-landscape/challenges/challenge-01-write-a-rules-of-engagement.md) |
| Work lands as a commit in a repository you own, not a file on your desktop | the `Submission` line closing all thirty-six exercises, each naming a portfolio path — e.g. [`curriculum/week-05-injection-and-input-validation/exercises/exercise-01-exploit-then-parameterize.md`](curriculum/week-05-injection-and-input-validation/exercises/exercise-01-exploit-then-parameterize.md) |
| You read code you did not write and form a judgement on it | [`curriculum/week-11-secure-code-review/exercises/exercise-01-review-for-injection-and-authz.md`](curriculum/week-11-secure-code-review/exercises/exercise-01-review-for-injection-and-authz.md) — a pull request somebody else authored, reviewed cold from the diff |
| A fix is proved by a re-test, not by an assertion that it is fixed | [`curriculum/week-03-owasp-top-10-deep-dive/challenges/challenge-02-remediate-and-retest.md`](curriculum/week-03-owasp-top-10-deep-dive/challenges/challenge-02-remediate-and-retest.md) |
| Findings live in a store somebody can query, not a spreadsheet and not a chat thread | [`curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-03-triage-into-a-database.md`](curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-03-triage-into-a-database.md) |
| Scanners run in the pipeline as gates whose failure stops the build | [`curriculum/week-10-secure-sdlc-and-ci-cd-security/exercises/exercise-01-add-a-failing-security-gate.md`](curriculum/week-10-secure-sdlc-and-ci-cd-security/exercises/exercise-01-add-a-failing-security-gate.md) |
| Secrets stay out of source and out of git history, and are rotated the moment they leak | [`curriculum/week-07-secrets-management-and-applied-crypto/exercises/exercise-01-scan-and-purge-secrets.md`](curriculum/week-07-secrets-management-and-applied-crypto/exercises/exercise-01-scan-and-purge-secrets.md) |
| A finding is written so the developer who has to fix it can act on it — location, reproduction, impact, a source-level fix | [`curriculum/week-11-secure-code-review/lecture-notes/03-writing-actionable-findings.md`](curriculum/week-11-secure-code-review/lecture-notes/03-writing-actionable-findings.md) |
| Tests exist and the command to run them is written down | Partly, and the course says so. C50 ships no test suite of its own — the learner writes the checks: the data-driven role × resource × action matrix in [`curriculum/week-06-access-control-and-authorization/exercises/exercise-03-authz-test-matrix.md`](curriculum/week-06-access-control-and-authorization/exercises/exercise-03-authz-test-matrix.md), and `python -m pytest tests/` wired as a blocking pipeline step in [`curriculum/week-12-capstone-secure-application/lecture-notes/02-building-security-in.md`](curriculum/week-12-capstone-secure-application/lecture-notes/02-building-security-in.md) |
| Failure is read off real output rather than imagined | C50 has no `Common bugs to catch` section. Twenty of its thirty-six exercises instead carry an `Expected result` block stating the output a correct run produces, so a learner can tell a broken run from a working one — e.g. [`curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-02-run-a-dast-scan.md`](curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-02-run-a-dast-scan.md) |
| Dependencies are pinned and audited, not merely installed | [`curriculum/week-09-api-and-supply-chain-security/exercises/exercise-03-generate-and-scan-an-sbom.md`](curriculum/week-09-api-and-supply-chain-security/exercises/exercise-03-generate-and-scan-an-sbom.md) |

**Beyond both bars.** Clearing the two floors is entry, not success. Open any of these and check it in under a minute.

| What we add | Which bar it beats | Where it lives |
| --- | --- | --- |
| Every quiz question publishes its answer, and the reasoning behind the answer, in the same file the question is asked in — nothing held back until a deadline | both | [`curriculum/week-03-owasp-top-10-deep-dive/quiz.md`](curriculum/week-03-owasp-top-10-deep-dive/quiz.md) |
| Twelve weeks of offensive work run inside a lab the learner owns and **proves** isolated, governed by a rules-of-engagement document they write and sign themselves before touching a target | both | [`curriculum/week-01-appsec-foundations-and-threat-landscape/lecture-notes/03-building-a-legal-isolated-lab.md`](curriculum/week-01-appsec-foundations-and-threat-landscape/lecture-notes/03-building-a-legal-isolated-lab.md) |
| Findings are data from Week 1 onward — one SQL store carried across the whole course, so "what is still open" is a query and not a memory | both | [`curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-03-triage-into-a-database.md`](curriculum/week-08-sast-dast-and-sca-tooling/exercises/exercise-03-triage-into-a-database.md) |
| The learner writes a static-analysis rule of their own for an app-specific pattern no public ruleset flags, and proves it fires on the bad case and stays silent on the safe one | both | [`curriculum/week-08-sast-dast-and-sca-tooling/challenges/challenge-01-write-a-custom-sast-rule.md`](curriculum/week-08-sast-dast-and-sca-tooling/challenges/challenge-01-write-a-custom-sast-rule.md) |
| A measured bake-off between the learner's own manual review and a scanner run over the same code, reported honestly in both directions — including where the scanner won | industry | [`curriculum/week-11-secure-code-review/challenges/challenge-02-review-versus-scanner.md`](curriculum/week-11-secure-code-review/challenges/challenge-02-review-versus-scanner.md) |
| The learner attacks their own build pipeline through a context-expression injection, patches it, then builds the detector for the pattern | university | [`curriculum/week-10-secure-sdlc-and-ci-cd-security/challenges/challenge-02-attack-and-defend-a-pipeline.md`](curriculum/week-10-secure-sdlc-and-ci-cd-security/challenges/challenge-02-attack-and-defend-a-pipeline.md) |
| The course ends in a design-defense review — a reviewer's questions answered and a signed residual-risk statement the learner keeps — rather than a mark only a registrar can see | both | [`curriculum/week-12-capstone-secure-application/challenges/challenge-02-capstone-defense-review.md`](curriculum/week-12-capstone-secure-application/challenges/challenge-02-capstone-defense-review.md) |

**Gaps we declare.** None against the secure-software-development outcome set. Two honest limits sit outside it and C50 does not claim either: the course ships no test suite of its own — every check is one the learner writes — and it does not teach binary exploitation, reverse engineering or malware analysis, which belong to the offensive-security track, not here.

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
