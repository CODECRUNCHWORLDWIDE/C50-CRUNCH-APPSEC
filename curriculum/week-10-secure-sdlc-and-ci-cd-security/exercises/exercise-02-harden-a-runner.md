# Exercise 2 — Harden a Runner

**Goal:** Close `PIPE-2` through `PIPE-5` — pin every third-party action to a commit SHA, add a least-privilege `permissions:` block, remove the hardcoded credential from the workflow file, and replace the unpinned `curl | bash` install with a checksum-verified one — then confirm the pipeline still runs clean end to end.

**Estimated time:** 90 minutes.

## Before you start

Confirm Exercise 1's gates are in place and passing:

```bash
cd ~/c50-week-10/crunch-deploy
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest   # SAST and SCA/secret-scan steps both green
```

## Task 1 — Pin every third-party action to a commit SHA (`PIPE-2`)

Look up the current commit SHA behind the tag each action uses — either from the action repository's release page, or with `git ls-remote`:

```bash
git ls-remote --tags https://github.com/actions/checkout v4.2.2
git ls-remote --tags https://github.com/actions/setup-python v5.3.0
```

Replace both `uses:` lines:

```yaml
# BEFORE
- uses: actions/checkout@v4
- uses: actions/setup-python@v5

# AFTER -- exact commit, human-readable version kept as a trailing comment
- uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v4.2.2
- uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b # v5.3.0
```

(If the SHAs above don't match what you resolve locally — release tags get repointed and superseded over time — use the exact SHA your own `git ls-remote` returns; the specific hash matters less than the fact that it's a SHA and not a mutable tag.)

## Task 2 — Add a least-privilege `permissions:` block (`PIPE-3`)

Crunch Deploy's job only reads the repository and runs tests — it never pushes, tags, releases, or writes packages. State that explicitly at the top of the workflow:

```yaml
permissions:
  contents: read
```

Run `act push` again and confirm the job still completes — a correctly-scoped `permissions:` block should not break anything this pipeline actually needs to do. If a later step ever fails specifically with a permissions-related error, that's a signal to add exactly the one scope that step needs, not to fall back to broad defaults.

## Task 3 — Remove the hardcoded credential (`PIPE-4`)

The baseline embeds `DEPLOY_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE` directly in the YAML. Remove the hardcoded value and reference GitHub Actions' own secrets context instead:

```yaml
# BEFORE
      - name: Deploy
        env:
          DEPLOY_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
        run: |
          curl -sSf https://example-ci-helper.test/install.sh | bash
          bash deploy/deploy.sh

# AFTER (secret reference; the fixed curl|bash line is replaced in Task 4)
      - name: Deploy
        env:
          DEPLOY_ACCESS_KEY: ${{ secrets.DEPLOY_ACCESS_KEY }}
        run: bash deploy/deploy.sh
```

Since this pipeline never leaves your machine, there's no real GitHub secrets store to configure — `act` reads secrets from a local, **gitignored** file instead. Create it:

```bash
echo 'DEPLOY_ACCESS_KEY=lab-only-placeholder-value' > .secrets.local
echo '.secrets.local' >> .gitignore
```

Run the pipeline passing that file explicitly:

```bash
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest --secret-file .secrets.local
```

Confirm with `git log -p -1 -- .github/workflows/deploy.yml | grep -i AKIA` that the credential no longer appears anywhere in the current workflow file. It still exists in the **first** commit's history (the insecure baseline) — note that in `PIPE-4-notes.md`: a secret removed from the current file but still present in git history is **not fully remediated** in a real repository; it must be rotated (treated as burned) and, if the repo isn't brand new, scrubbed from history with a tool built for that (see `resources.md`). This exercise doesn't require you to rewrite this lab repo's history — just write down, accurately, why "I deleted the line" alone would not be a complete fix in a real project.

## Task 4 — Kill the unpinned `curl | bash` step (`PIPE-5`)

Replace the network-fetched-and-executed installer with a pinned, checksum-verified download of a specific release archive instead of piping an install script straight into a shell:

```yaml
      - name: Install Trivy (pinned + checksum-verified)
        run: |
          TRIVY_VERSION="0.58.1"
          curl -sSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
          curl -sSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
          grep "Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -
          tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy
          sudo mv trivy /usr/local/bin/trivy
```

(Substitute the current release version and its published checksum file — the point isn't this exact version number, it's that you fetch a **specific, versioned artifact** and **verify its checksum** before executing anything, instead of trusting whatever a mutable install-script URL happens to serve today.) Fold this in as your Exercise 1 Trivy step's replacement.

## Task 5 — Full pipeline run, gate results recorded

```bash
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest --secret-file .secrets.local
```

Confirm every step passes, then record the hardening as a `gate_runs` row (there's no scanner tool for "runner hardening" itself, so log it as a manual control check):

```python
import sqlite3
conn = sqlite3.connect("pipeline.db")
conn.execute(
    "INSERT INTO gate_runs (run_id, gate, tool, status, findings_count) VALUES (?, ?, ?, ?, ?)",
    ("run-003", "sca", "manual-runner-hardening-check", "pass", 0),
)
conn.commit()
```

## Expected result

- `deploy.yml` has zero `@v` or `@main`-style mutable references — every `uses:` is a commit SHA.
- A top-level `permissions: { contents: read }` block is present, and the pipeline still completes.
- `git grep -i AKIA -- .github/workflows/deploy.yml` (current tree, not history) returns nothing.
- No step pipes a `curl` response directly into `bash` or `sh` without a preceding checksum verification.

## Done when…

- [ ] All four fixes (`PIPE-2`–`PIPE-5`) are present in `deploy.yml`.
- [ ] `.secrets.local` exists, is gitignored, and is never referenced by a hardcoded value anywhere in the workflow.
- [ ] `PIPE-4-notes.md` correctly explains why deleting a hardcoded secret from the current file doesn't fully remediate it if that secret already exists in git history.
- [ ] You can explain, without looking it up, what a repointed tag on a third-party action could do that a pinned SHA cannot.

## Stretch

- Add `timeout-minutes: 10` at the job level if you didn't already in Exercise 1's stretch goal.
- Research (don't implement — this lab has no real cloud provider) what OpenID Connect (OIDC) federation would replace `DEPLOY_ACCESS_KEY` with in a pipeline that deploys to a real cloud account, and write 3–4 sentences on why a token that expires in minutes is a smaller standing liability than a long-lived key sitting in a secret store.

## Submission

Commit the updated `.github/workflows/deploy.yml`, `.gitignore`, `.secrets.local.example` (a placeholder version — never the real one), `PIPE-4-notes.md`, and updated `pipeline.db` to `c50-week-10/exercise-02/`.
