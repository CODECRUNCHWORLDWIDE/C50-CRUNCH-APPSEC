# Week 10 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Docker Desktop or Docker Engine** — <https://www.docker.com/products/docker-desktop/> — `act` uses it to simulate GitHub-hosted runners locally.
- **`act`** — <https://github.com/nektos/act> — macOS: `brew install act`. Linux: download the release binary from the releases page rather than piping an install script into `bash` (see Lecture 2 for exactly why).
- **Semgrep** — `pip install semgrep` — <https://semgrep.dev/docs/getting-started/> — reused from Week 8 as this week's SAST gate.
- **Trivy** — <https://trivy.dev/latest/getting-started/installation/> — reused from Week 8 as this week's SCA + secret-scan gate.
- **GnuPG (`gpg`)** — usually preinstalled on macOS/Linux; if not, <https://gnupg.org/download/> — this week's artifact-signing tool.
- **Python 3.10+** — `sqlite3` ships with Python; no separate install.

## This week's lab pipeline

- **Crunch Deploy** — full source (`app.py`, `requirements.txt`, `tests/`, `.github/workflows/deploy.yml`, `deploy/deploy.sh`) is in the [week README](./README.md). It's your own local project — there's no external download; you build it once and harden it all week.

## Required reading (this week's core)

- **GitHub — Security hardening for GitHub Actions:** <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions>
  *Why: the official source for Lecture 2's pinning, permissions, and secrets guidance — the single most important doc this week.*
- **GitHub — Security hardening for `GITHUB_TOKEN`:** <https://docs.github.com/en/actions/security-guides/automatic-token-authentication>
  *Why: exact default-permission behavior behind `PIPE-3` and Exercise 2's `permissions:` block.*
- **GitHub Security Lab — Understanding the risk of script injection:** <https://securitylab.github.com/resources/github-actions-untrusted-input/>
  *Why: the deep-dive on the exact context-expression injection pattern Lecture 2 Section 5 and Challenge 2 are built on.*
- **OWASP — Top 10 CI/CD Security Risks:** <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
  *Why: the community-maintained catalog Lecture 2's four risk categories map onto.*
- **Semgrep — CI mode and exit codes:** <https://semgrep.dev/docs/semgrep-ci/overview/>
  *Why: how `--error` and CI-specific configuration turn a scan into a gate.*
- **Trivy — Exit codes and CI integration:** <https://trivy.dev/latest/docs/configuration/exit-code/>
  *Why: the `--exit-code` flag Exercise 1 depends on.*

## Reference (keep in tabs)

- **`act` — Documentation:** <https://nektosact.com/>
- **GitHub Actions — Workflow syntax reference:** <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions>
- **GitHub Actions — Contexts (`github.event`, etc.):** <https://docs.github.com/en/actions/learn-github-actions/contexts>
- **Sigstore — cosign documentation:** <https://docs.sigstore.dev/cosign/overview/>
- **SLSA — Supply-chain Levels for Software Artifacts:** <https://slsa.dev/>
- **in-toto — supply-chain integrity attestation framework:** <https://in-toto.io/>
- **GnuPG — detached signatures (manual excerpt):** <https://www.gnupg.org/gph/en/manual/x135.html>
- **NIST SP 800-218 — Secure Software Development Framework (SSDF):** <https://csrc.nist.gov/pubs/sp/800/218/final>
- **OWASP SAMM (Software Assurance Maturity Model):** <https://owaspsamm.org/>
- **git-filter-repo** (for scrubbing a secret from git history — referenced in Exercise 2's notes, not required to run this week): <https://github.com/newren/git-filter-repo>

## Practice beyond this week's lab

- **GitHub — "Awesome Actions" curated list** (read a handful of real, well-maintained workflows to see pinning/permissions conventions in the wild): <https://github.com/sdras/awesome-actions>
- **OWASP DevSecOps Guideline** (a fuller maturity-model view beyond one week's single pipeline): <https://owasp.org/www-project-devsecops-guideline/>

## Deeper background (optional this week)

- **CISA/NSA/ODNI — Securing the Software Supply Chain: Recommended Practices for Developers:** <https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-developers>
- **SolarWinds Orion supply-chain compromise — CISA overview:** <https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software>
  *Why: the build-time tampering incident referenced throughout Lecture 2 and Lecture 3.*
- **Codecov Bash Uploader compromise — public incident writeup:** <https://about.codecov.io/security-update/>
  *Why: the second real-world build-script compromise referenced in Lecture 2 Section 1.*

## Glossary

| Term | Definition |
|------|------------|
| **Shift-left** | Moving security activities earlier in the SDLC, where fixes are cheaper and the original context is still fresh — not a promise to eliminate later-phase checks entirely. |
| **Security gate** | A pipeline step whose non-zero exit code stops the build, as opposed to a scan that only produces a report. |
| **SAST / SCA / secret scan** | Static analysis of source (SAST), dependency vulnerability lookup (SCA), and detection of credentials accidentally committed to source (secret scan) — see Week 8 for SAST/SCA in depth. |
| **Least privilege (runner)** | Granting a CI job's identity (`GITHUB_TOKEN`, cloud credentials) only the exact scopes that job needs, defaulting everything else to none. |
| **Pinning (to a SHA)** | Referencing a dependency, action, or container image by its exact, immutable commit/digest identity rather than a mutable tag or branch name. |
| **Context-expression injection** | Untrusted event data (e.g., an issue title) interpolated directly into a `run:` block's shell text via `${{ }}`, allowing it to be parsed as shell syntax rather than treated as data. |
| **Artifact signing** | Cryptographically signing a build output so its authenticity and integrity can be verified before it's deployed. |
| **Keyless signing (Sigstore/cosign)** | Signing bound to a short-lived, per-build identity certificate (via OIDC) instead of a long-lived private key a human or system must protect and rotate. |
| **SLSA provenance** | A signed attestation describing exactly which pipeline, from which source commit, produced a given artifact — a stronger claim than "this was signed by some key." |
| **`act`** | An open-source tool that runs GitHub Actions workflows locally in Docker, without any real GitHub repository or network dependency on GitHub itself. |
| **Accepted-risk exception** | A written, time-boxed, reviewed decision to allow a specific known finding past a gate, as opposed to a silent suppression with no justification or expiry. |

---

*Broken link? Open an issue or PR.*
