# Exercise 3 — Sign and Verify an Artifact

**Goal:** Close `PIPE-6` — build Crunch Widgets into a tarball, GPG-sign it as a pipeline step, and gate the deploy step on a passing signature verification, so a missing or invalid signature stops the deploy before it runs.

**Estimated time:** 60 minutes.

## Before you start

Confirm Exercise 2's hardened pipeline still runs clean:

```bash
cd ~/c50-week-10/crunch-deploy
act push -P ubuntu-latest=catthehacker/ubuntu:act-latest --secret-file .secrets.local
```

## Task 1 — Generate a lab-only signing key

**Do this once, on your own host — not inside the `act` container, which is disposable.** This key exists only for this week's lab; never reuse it for anything real.

```bash
gpg --quick-generate-key "Crunch Deploy CI <ci@crunch-deploy.lab>" ed25519 sign 1y
gpg --list-secret-keys --keyid-format long "ci@crunch-deploy.lab"
```

Export the private key so the pipeline can use it (in a real pipeline this becomes a platform secret, never a repo file — export it to a local, gitignored path):

```bash
gpg --export-secret-keys --armor "ci@crunch-deploy.lab" > ci-signing-key.asc
echo 'ci-signing-key.asc' >> .gitignore
```

## Task 2 — Add a build + sign step

Add this step to `.github/workflows/deploy.yml`, after the tests pass and before the deploy step:

```yaml
      - name: Build and sign artifact
        run: |
          tar -czf crunch-widgets.tar.gz app.py requirements.txt
          gpg --import ci-signing-key.asc
          gpg --detach-sign --armor -u "ci@crunch-deploy.lab" crunch-widgets.tar.gz
```

(The exported key file needs to actually be present for `act` to import it — copy `ci-signing-key.asc` into the project directory before running, and confirm your `.gitignore` keeps it out of any commit.)

## Task 3 — Add a verify-before-deploy gate

Add a verification step immediately before the deploy step, and make the deploy step depend on it succeeding:

```yaml
      - name: Verify artifact signature
        run: gpg --verify crunch-widgets.tar.gz.asc crunch-widgets.tar.gz

      - name: Deploy
        env:
          DEPLOY_ACCESS_KEY: ${{ secrets.DEPLOY_ACCESS_KEY }}
        run: bash deploy/deploy.sh
```

Because these are sequential steps in the same job, a failing `gpg --verify` (non-zero exit) stops the job before the `Deploy` step ever runs — no extra wiring needed.

## Task 4 — Prove it: tamper with the artifact and confirm deploy is refused

Run the full pipeline once and confirm it deploys successfully. Then simulate exactly the SolarWinds/Codecov scenario from Lecture 2 — an artifact quietly modified **after** signing, **before** deploy:

```bash
tar -czf crunch-widgets.tar.gz app.py requirements.txt
gpg --detach-sign --armor -u "ci@crunch-deploy.lab" crunch-widgets.tar.gz
echo "malicious payload" >> crunch-widgets.tar.gz     # simulate tampering
gpg --verify crunch-widgets.tar.gz.asc crunch-widgets.tar.gz; echo "exit code: $?"
```

Confirm the verify step's exit code is now non-zero, and that a manual re-run of the pipeline with this tampered artifact in place stops at the verify step, never reaching `Deploy`.

## Task 5 — Record signature events

```python
import sqlite3, hashlib

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

conn = sqlite3.connect("pipeline.db")

# clean artifact, signed and verified successfully
conn.execute(
    "INSERT INTO signatures (artifact, digest, signed_by, verified) VALUES (?, ?, ?, ?)",
    ("crunch-widgets.tar.gz", sha256_of("crunch-widgets.tar.gz"), "ci@crunch-deploy.lab", 1),
)
conn.execute(
    "INSERT INTO gate_runs (run_id, gate, tool, status, findings_count) VALUES (?, ?, ?, ?, ?)",
    ("run-004", "signing", "gpg", "pass", 0),
)
conn.commit()

for row in conn.execute("SELECT * FROM signatures"):
    print(row)
```

Re-run Task 4's tamper scenario against a fresh artifact, and add a `gate_runs` row with `status = 'fail'` for that attempt — your database should show both outcomes, the same "prove the fix, then prove the failure mode too" discipline every prior week's mini-projects have used.

## Expected result

- A clean pipeline run signs the artifact, verifies it, and deploys.
- A tampered artifact fails verification with a non-zero exit code, and the deploy step never runs.
- `signatures` has at least one `verified = 1` row for a clean artifact; `gate_runs` has both a `pass` and a `fail` row for the `signing` gate.

## Done when…

- [ ] `deploy.yml`'s deploy step is unreachable unless the immediately preceding `gpg --verify` step exits `0`.
- [ ] You've demonstrated, with a real tampered file, that verification correctly fails.
- [ ] `ci-signing-key.asc` is gitignored and never appears in `git status` as staged or committed.
- [ ] You can explain, without looking it up, what artifact signing proves that the SAST/SCA gates from Exercise 1 do not.

## Stretch

- Read `resources.md`'s Sigstore/cosign links and write 3–4 sentences on what would change about **key management** specifically if you replaced this exercise's long-lived GPG key with cosign's keyless, OIDC-bound signing — you don't need to install cosign to answer this.
- Add a `digest` check as a second, independent verification layer: compute `sha256sum crunch-widgets.tar.gz` at build time, store it, and re-check it at deploy time in addition to the GPG signature — redundant integrity checks are a legitimate defense-in-depth pattern, not wasted effort.

## Submission

Commit the updated `.github/workflows/deploy.yml`, the tamper-test transcript, and updated `pipeline.db` to `c50-week-10/exercise-03/`. **Do not** commit `ci-signing-key.asc` or `.secrets.local` — confirm both are gitignored before you push anything.
