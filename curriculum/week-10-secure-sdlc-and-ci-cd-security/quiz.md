# Week 10 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 11. A mix of multiple-choice and short "what would you fix here" — the answer key at the bottom explains the *why*, not just the letter.

---

**Q1.** Which of these is the best description of "security across the SDLC"?

- A) Running one penetration test right before launch
- B) Spreading the right security activity across every phase — requirements, design, build, test, deploy, operate
- C) Hiring a dedicated security team so developers don't have to think about it
- D) Running every scanner available at every phase, regardless of cost

---

**Q2.** An abuse case belongs in which SDLC phase?

- A) Deploy
- B) Operate
- C) Requirements
- D) Test only

---

**Q3.** Why does a CI/CD pipeline often deserve more hardening attention than the application it builds?

- A) Pipelines are always written in less secure languages
- B) The pipeline typically holds more privilege — deploy keys, signing keys, broad repo access — than the app itself
- C) Applications are never actually attacked in practice
- D) Pipelines cannot be scanned by SAST tools

---

**Q4.** What's the key difference between `uses: actions/checkout@v4` and pinning to a commit SHA?

- A) There is no difference; both always resolve to the same code
- B) A tag can be silently repointed to different code later; a SHA cannot change out from under you
- C) SHAs are slower to resolve at runtime
- D) Tags are more secure because they're human-readable

---

**Q5.** A workflow triggered by `pull_request_target` that also checks out and executes a fork's code is risky because:

- A) It always fails to run
- B) It runs with the base repository's permissions and secrets against untrusted, attacker-controlled code
- C) `pull_request_target` disables all secrets by default, so nothing bad can happen
- D) Forks cannot trigger any workflow, so this scenario is impossible

---

**Q6.** `permissions: contents: read` at the top of a workflow accomplishes:

- A) Nothing; permissions can only be set per-step
- B) It prevents the workflow from running at all
- C) It scopes the auto-generated `GITHUB_TOKEN` down from its broad default, following least privilege
- D) It grants write access to package registries automatically

---

**Q7.** Given `run: echo "${{ github.event.issue.title }}"`, what makes this dangerous?

- A) `echo` cannot safely print any string
- B) The substitution happens as literal text before the shell parses the command, so attacker-controlled text can inject new shell syntax
- C) Issue titles are always encrypted, so this can never leak data
- D) This syntax is invalid and the workflow would fail to run

---

**Q8.** The fix for context-expression injection into a `run:` block is to:

- A) Add more quotes around the `${{ }}` expression
- B) Bind the untrusted value to an environment variable first, then reference it as a shell variable (e.g., `$TITLE`) inside `run:`
- C) Disable the workflow entirely
- D) Base64-encode the run command

---

**Q9.** Trivy's `--exit-code 1` flag matters because:

- A) Without it, Trivy refuses to run at all
- B) Without it, Trivy still prints findings but always exits `0`, so a pipeline step running it would always "pass" regardless of findings
- C) It's required to enable secret scanning
- D) It changes which vulnerability database Trivy queries

---

**Q10.** Why is a zero-tolerance security gate (fails the build on any finding, of any severity) often worse for security in practice than a tuned one?

- A) Zero-tolerance gates are technically impossible to configure
- B) It trains developers to route around or disable the gate, the same alert-fatigue problem untriaged scanner output causes
- C) Severity levels don't actually exist in real scanners
- D) It makes the pipeline run faster

---

**Q11.** What does artifact signing prove that a passing SAST/SCA gate does not?

- A) That the source code has no bugs
- B) That the exact artifact being deployed is the one that was built and approved — not something substituted after the gates ran
- C) That the deploy credentials are valid
- D) That the application has no runtime vulnerabilities

---

**Q12.** What is the key difference between this week's GPG signing technique and Sigstore/cosign's keyless approach?

- A) GPG cannot produce a valid signature
- B) Cosign's keyless approach binds a short-lived certificate to the pipeline's own identity per build, rather than relying on a long-lived key someone must protect and rotate
- C) GPG signatures cannot be verified by anyone but the signer
- D) There is no meaningful difference; they solve unrelated problems

---

**Q13.** In the `gate_runs` table from this week's schema, a properly gated pipeline's history should show:

- A) Only `pass` rows — a `fail` row means the schema is broken
- B) Both historical `fail` rows (from before fixes) and current `pass` rows — the record of what a gate actually caught
- C) No rows at all until the mini-project
- D) Exactly one row per week, regardless of how many times the pipeline ran

---

**Q14.** Why does the SolarWinds-style attack (tampering during the build step) specifically defeat a code review of the application's own source?

- A) Code review is never effective against any attack
- B) The tampering happens in the build process itself, not in a source file a reviewer would ever read
- C) SolarWinds didn't actually involve a build-time compromise
- D) Code review tools cannot read YAML files

---

**Q15.** A workflow step installs a CLI tool via `curl -sSf https://example.test/install.sh | bash` with no further verification. The specific risk category this represents is:

- A) Over-privileged runner
- B) Leaked secret
- C) Poisoned/unverified dependency — the script's content can change at the source with no way to detect it
- D) Context-expression injection

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — the whole point of "across the SDLC" is that no single late phase (like a pre-launch pentest) carries the entire security burden.
2. **C** — abuse cases are written alongside functional requirements, before design or code exist.
3. **B** — a compromised pipeline can affect every system it deploys to and every future build it produces, which is usually a larger blast radius than one compromised application instance.
4. **B** — a tag is a mutable pointer; whoever controls that upstream repository can repoint it. A SHA identifies one specific, immutable commit.
5. **B** — `pull_request_target` runs with the base repo's trust level (permissions, secrets) even though the code it may check out comes from an untrusted fork.
6. **C** — without an explicit `permissions:` block, `GITHUB_TOKEN` defaults to a broad read/write scope; stating `contents: read` (or whatever the job actually needs) scopes it down.
7. **B** — GitHub Actions substitutes `${{ }}` expressions into the run text before the shell ever parses it, so attacker-controlled content can contain live shell syntax.
8. **B** — routing the value through `env:` means the shell only ever sees a variable reference (`$TITLE`) in the command; the actual attacker-controlled content is bound as data, never re-parsed as command syntax.
9. **B** — Trivy always reports what it finds, but only `--exit-code 1` (or similar) turns a finding into a failing exit code a pipeline step can act on.
10. **B** — the same alert-fatigue dynamic Week 8 taught for scanner triage applies at build-gate time: an unreasonable gate gets bypassed, disabled, or ignored rather than fixed.
11. **B** — SAST/SCA gates check the source; signing proves the specific artifact that reaches deploy is unmodified since it passed those gates — closing exactly the gap SolarWinds/Codecov exploited.
12. **B** — keyless signing avoids a long-lived private key entirely by binding a short-lived, per-build certificate to the pipeline's own verifiable identity.
13. **B** — a posture database that only ever shows clean passes either never ran during active development, or isn't recording history honestly; showing the fail-then-fix arc is the point.
14. **B** — the malicious modification happens during the build process (compiling, linking, packaging), a step no source-code reviewer is looking at, because the source code itself was never altered.
15. **C** — fetching and executing a remote script with no pinning or checksum verification is exactly the poisoned/unverified-dependency risk category, whether the "dependency" is a library or a CLI installer.

</details>

**Scoring:** 12+ → start Week 11. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; the concepts compound fast next week.
