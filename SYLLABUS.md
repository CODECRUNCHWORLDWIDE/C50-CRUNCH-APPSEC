# C50 · Crunch AppSec — Syllabus

**Format:** 12 weeks · self-paced · open-source (GPL-3.0). Each week = 3 lectures, 3 exercises, 2 challenges, a mini-project, homework, and a quiz.

**Prerequisites:** You can run commands in a terminal, read and write basic code in one language, and have built or seen a simple web app (a backend + a database). Comfort with HTTP and SQL helps — [C16 Crunch Pro Web Backend](../C16-CRUNCH-PRO-WEB-BACKEND/) and [C33 Crunch SQL](../C33-CRUNCH-SQL/) are ideal companions. No security background assumed.

**Ethics & legality (binding):** All work is **authorized, legal, defensive** security practiced **only in isolated lab environments you own** — deliberately-vulnerable VMs, sandboxes, and CTF targets. **Never** target a real third-party system. Every offensive technique is tied to a detection and a fix. Malware/reverse-engineering runs **only in a no-network sandbox**. Written authorization, defined scope, and the law govern every exercise.

**Assessment (honor-based):** tick each lesson complete in the reader; finish the weekly mini-project and quiz. A certificate is issued on 100% completion to One-Stop members.

| Week | Theme | Mini-project |
|------|-------|--------------|
| 1 | AppSec foundations + attacker/defender view + lab setup | Stand up an isolated lab; write assets/threats/risk register |
| 2 | Threat modeling with STRIDE + data-flow diagrams | STRIDE-model a target app; rank mitigations |
| 3 | OWASP Top 10 in depth — demo + fix each risk class | Build a Top 10 "demonstrate + remediate" evidence report |
| 4 | Authentication — password storage, MFA, session security | Harden a broken login/session flow against known attacks |
| 5 | Injection + input validation; parameterized SQL as defense | Convert an injectable app to parameterized queries + validation |
| 6 | Access control + authorization — RBAC/ABAC, deny-by-default | Fix IDOR + privilege escalation with fail-closed authz |
| 7 | Secrets management + applied crypto (hash/encrypt/sign) | Remove hardcoded secrets; fix a broken-crypto feature |
| 8 | SAST + DAST + SCA tooling and triage | Wire scanners into a pipeline; triage a findings backlog |
| 9 | API security + software supply-chain security | Secure an API + lock the dependency/SBOM supply chain |
| 10 | Secure SDLC + CI/CD pipeline security | Add security gates to an SDLC + harden a CI/CD pipeline |
| 11 | Secure code review — reading code for vulnerabilities | Review a PR for vulns; write a prioritized findings report |
| 12 | Capstone — threat-model, build, test, and defend an app | Ship + defend a small secure application end to end |

**Outcome:** threat-model a system, find and fix the vulnerability classes that matter, automate the hunt, and ship software that holds up — with security built into the SDLC, not bolted on.
