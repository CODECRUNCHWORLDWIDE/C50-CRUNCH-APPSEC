# Lecture 1 — Where Secrets Leak

> **Duration:** ~2 hours. **Outcome:** You can name every place a secret hides in a real codebase — source, config, environment, logs, and git history — scan for each with a real tool, and describe a management model (vault + env injection + rotation) that closes the leak instead of just hiding the symptom.

A **secret** is any value that grants access if it falls into the wrong hands: an API key, a database password, a signing key, an OAuth client secret, a TLS private key, an SSH key. Secrets don't leak because developers are careless in some abstract sense — they leak because storing a secret as a plain string, in the most convenient place at the time, is *always* the path of least resistance, and the convenient place is almost never the safe place. This lecture walks the five places secrets hide, in the order attackers (and scanners) actually check them.

## 1. Secrets in source

The most direct leak: a literal string, in a `.py`/`.js`/`.java`/`.go` file, checked straight into the repo.

```python
# config.py -- from this week's lab
API_KEY = "sk_live_REDACTED-EXAMPLE-not-a-real-key"
DB_PASSWORD = "Vault_Admin_2024!"
```

Why it happens: it's the fastest way to get something working, and it "works" in every environment without extra setup — right up until the repo is cloned by someone who shouldn't have that key, or the repo (or a fork, or a CI log that echoes the file) goes public.

**Grep for the obvious ones yourself, right now, against this week's lab:**

```bash
cd ~/c50-week-07/leaky-crunch-vault
grep -rniE "(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}" --include="*.py" .
```

That single regex — a variable name that *smells like* a secret, assigned a quoted string of reasonable length — is most of what a basic secret scanner does. It's crude (false positives on things like `password_hint = "your pet's name"`) and it's exactly why dedicated scanners (Section 4) use curated, high-precision patterns per secret *type* instead of one generic regex.

## 2. Secrets in config files

One step removed from source, but no safer: `settings.yaml`, `application.properties`, `docker-compose.yml`, `terraform.tfvars` — any structured config file that ends up in the repo.

```yaml
# docker-compose.yml -- a common leak vector
services:
  api:
    environment:
      DATABASE_URL: "postgres://admin:Vault_Admin_2024!@db:5432/crunch"
```

The failure mode is identical to source: the file is versioned, so the secret is versioned. Config files get a false sense of safety because they "feel" like data, not code — but git doesn't know the difference, and neither does an attacker who clones the repo.

## 3. Secrets in environment files

`.env` files exist specifically to keep secrets *out* of source and config — inject them as environment variables at runtime instead. That's the right idea, executed wrong the moment the `.env` file itself gets committed:

```bash
# .env -- from this week's lab setup
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_REDACTED-EXAMPLE-not-a-real-key
```

`.env` should be in `.gitignore` **before** it's ever created, not added after the first commit. Once it's committed once, being in `.gitignore` going forward does nothing for the copy already in history — which is exactly the trap Section 5 covers.

## 4. Secrets in logs

Logging exists to record what happened. It's very easy to accidentally record *what was sent*, including the secret itself:

```python
# app.py -- from this week's lab, VULN #3
log.info("Storing secret label=%s value=%s", label, secret)
```

This is a quieter leak than source or `.env`, because the secret never shows up in a code review — it shows up hours or months later, in a log file, on disk, and usually copied into a log aggregation service (Splunk, Datadog, CloudWatch) with a *much* larger set of people who can read it than the people who can read the source repo. The fix is a discipline, not a tool: **never log a secret value, not even at debug level, not even "temporarily."** Log that an action happened (`"Storing secret label=%s"`) and stop there — the value itself adds nothing a responder needs and everything an attacker wants.

```mermaid
flowchart TD
  A["Secret leaks in source or .env"] --> B["Committed to git"]
  B --> C["Pushed to a shared/remote repo"]
  C --> D["Cloned, forked, or CI checks it out"]
  D --> E["Logged in plaintext by the running app"]
  E --> F["Shipped to a log aggregator\nwith broad read access"]
  F --> G["Secret is now effectively public\nwithin the org, or beyond it"]
```
*Each hop widens the audience. By the time a secret reaches a log aggregator, "who can see this" is usually a much bigger set of people than the original committer ever considered.*

## 5. Secrets in git history

This is the leak that survives every fix above. Git is a history of **every version of every file that was ever committed** — deleting a file, or editing it, does not delete the old blob; it just stops pointing the latest commit at it. The blob is still reachable from any earlier commit, forever, unless the history itself is rewritten.

Recall from this week's lab setup:

```bash
git rm -q .env
echo ".env" >> .gitignore
git add .gitignore
git commit -q -m "Remove .env from repo, add to gitignore"
```

The file is gone from the working tree and from `HEAD`. It is **not** gone from the repo:

```bash
git log --all --oneline -- .env         # shows the commit that added .env
git show <that-commit-hash>:.env        # prints the full file, secrets and all
git log -p --all -- .env | grep AKIA    # finds the key without even knowing the hash
```

Three ways this bites teams in practice:

1. **A public fork or mirror.** Even if the current `main` looks clean, anyone who cloned or forked the repo *before* the "removal" commit still has the secret in their local history, permanently.
2. **"We removed it, so it's fine."** The team closes the finding as fixed because the file is gone from the latest commit. The secret is still live and still readable — nothing about the *credential itself* has changed.
3. **Squash-merge false confidence.** Squashing a feature branch into one commit on `main` can *look* like it erased the secret's history, but the original branch commits (and any mirror/fork that has them) still contain it.

The only correct sequence, covered in depth in Exercise 1, is: **scan → confirm → rotate the actual credential → purge the history → verify the purge → prevent recurrence with a pre-commit scanner.** Rotation comes *before* history purging in that list on purpose — purging history is cleanup; rotation is the fix. A secret that was ever pushed to a remote must be treated as compromised regardless of whether you can still find it.

## 6. Secret scanning tools

Hand-rolled `grep` (Section 1) catches the obvious cases. Dedicated scanners catch far more, with fewer false positives, because they match structured, provider-specific patterns (an AWS access key is always `AKIA` + 16 uppercase alphanumerics; a Stripe live key always starts `sk_live_`) instead of a generic "looks secret-ish" heuristic:

| Tool | What it does | Where it runs |
|---|---|---|
| **gitleaks** | Regex + entropy-based scan of a repo's working tree *and* full git history | CLI, pre-commit hook, CI |
| **trufflehog** | Similar to gitleaks, plus live verification against some providers (is this key still active?) | CLI, CI |
| **detect-secrets** (Yelp) | Scans + maintains a baseline file so already-known/accepted matches don't re-fire | CLI, pre-commit hook |
| **git-secrets** (AWS Labs) | Pattern-based, AWS-key-focused, installs as a git hook | pre-commit / pre-push hook |
| **GitHub push protection / secret scanning** | Server-side, blocks pushes containing known secret patterns before they land | GitHub-hosted repos |

You'll wire one of these into the lab repo in Exercise 1, but the regex approach from Section 1 is worth understanding on its own — every one of these tools is, underneath, a curated pattern library plus (for the better ones) entropy scoring to catch secrets that don't match a known provider format.

## 7. A management model: vault, injection, rotation

Knowing where secrets leak only matters if you replace the leaky pattern with something that doesn't leak. The model that holds up in practice has three pieces:

**Vault or secrets manager** — a single system of record for secrets, access-controlled and audit-logged, separate from source control entirely: HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or (for smaller teams) even a well-locked-down password manager with team sharing. The defining property is not the product — it's that **the secret's source of truth is not a file in a repo.**

**Environment injection** — the running application reads secrets from its environment (`os.environ`) at startup, and *something else* is responsible for populating that environment: a `.env` file that is gitignored and never committed (local dev only), a CI secrets store injecting them as job-scoped env vars (GitHub Actions secrets, GitLab CI variables), or a vault agent/sidecar pulling them at deploy time in production. The app's code never contains the value — only the *name* of the variable it expects.

```python
# The only line of code that should ever mention a secret's VALUE is one
# that reads it from the environment -- never one that assigns it.
import os
api_key = os.environ["STRIPE_SECRET_KEY"]   # correct: reads, doesn't define
```

**Rotation** — a plan, exercised regularly (not just "when we get breached"), for issuing a new credential and retiring the old one, with an expiry window short enough that a leaked-but-undetected secret doesn't stay valid indefinitely. A rotation plan answers, concretely: who/what can rotate this credential, how long does the old value stay valid during cutover, and how is every consumer of the secret updated without downtime? A secret with no rotation plan is a secret you can never confidently call "fixed" after a leak — you can only hope it wasn't used.

```mermaid
flowchart LR
  dev["Developer's .env\n(local only, gitignored)"] -->|never committed| app1["App (local)"]
  ci["CI secrets store"] -->|injected as env vars| app2["App (CI/test)"]
  vault[("Vault / Secrets Manager\nsystem of record")] -->|pulled at deploy| app3["App (production)"]
  vault -->|rotation schedule| vault
```
*Three environments, three injection paths, one rule that never changes: the value lives in the vault or the environment, never in a file git tracks.*

## 8. Check yourself

- Name the five places a secret can leak, in the order this lecture covered them.
- Why is `.env` in `.gitignore` *after* the first commit not enough?
- What command lets you read a file's contents from three commits ago, even if the file no longer exists on `main`?
- Why does rotation come before history-purging in the remediation sequence?
- What's the difference between a generic `grep` secret scan and a tool like gitleaks?
- In the vault/injection/rotation model, what's the one thing that should *never* appear in application source code?
- Why is logging a secret's value a quieter leak than committing it to source, and why is it not a smaller problem?

If those are automatic, Lecture 2 moves from *finding and managing* secrets to *using cryptography correctly* once you have them safely stored.

## Further reading

- **OWASP Secrets Management Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- **gitleaks:** <https://github.com/gitleaks/gitleaks>
- **trufflehog:** <https://github.com/trufflesecurity/trufflehog>
- **detect-secrets:** <https://github.com/Yelp/detect-secrets>
- **GitHub — About secret scanning:** <https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning>
- **git — removing sensitive data from history:** <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
