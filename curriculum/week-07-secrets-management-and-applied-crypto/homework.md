# Week 7 — Homework

Five problems, ~4 hours total, spread across the week. All work happens against your own isolated lab (`leaky-crunch-vault`) or self-generated data — nothing here ever touches a real credential or a system you don't own. Commit each deliverable.

---

## Problem 1 — Audit a real open-source repo's secret hygiene, read-only (45 min)

Pick any small, popular open-source project on GitHub (your choice — a CLI tool, a library, anything with public history). **Read-only, no scanning tools, no cloning required** — just browse its repo settings and public security page.

In `oss-audit.md` (~250 words), answer:

1. Does the repo have GitHub secret scanning / push protection enabled (visible on its Security tab if the maintainers have made it public, or inferable from its `.github/` workflows)?
2. Does it have a `SECURITY.md` with a disclosure process?
3. Does it use a `.env.example` (placeholder-only) pattern, or does its `.gitignore` explicitly exclude `.env`/credentials files?

**Deliver** `oss-audit.md`. The skill here is recognizing secret-hygiene signals from the *outside*, the way a due-diligence review or a security-conscious contributor would, without needing write access or special tools.

---

## Problem 2 — Extend the findings database with a severity column (45 min)

Your `week07.db`'s `secret_findings` table tracks *what* and *status* but not *how bad*. Add a `severity` column and backfill it:

```sql
ALTER TABLE secret_findings ADD COLUMN severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical'));
```

For each existing row, assign a severity and write one sentence of justification in a companion `severity-notes.md` — e.g., a payment API key found in git history is `critical` (real financial exposure if it had been real); a false-positive match on `password_hint` (if you hit one during scanning) is appropriately `low` or reclassified as `false_positive` entirely.

**Deliver** the `ALTER TABLE` + `UPDATE` statements in `severity-backfill.sql`, plus `severity-notes.md`. Then write and run one query: `SELECT severity, COUNT(*) FROM secret_findings GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END;` and paste its output.

---

## Problem 3 — Explain "authenticated encryption" to a non-crypto engineer (45 min)

Write `explain-aead.md`, no more than 300 words, aimed at a hypothetical backend engineer on your team who knows what AES is but has never heard the term AEAD. It must:

1. Explain, without hand-waving, what problem plain AES-CBC (no authentication) leaves open that AES-GCM/Fernet closes.
2. Use a concrete example from this week's lab (the bit-flip tamper test from Exercise 2) rather than an abstract description.
3. End with one sentence of actionable guidance: what should this engineer reach for the next time they need to encrypt something, and what's the one thing they should never do instead.

**Deliver** `explain-aead.md`. This is the same "translate technical finding into something a colleague can act on" skill Week 1's homework introduced — it matters as much for crypto choices as it does for risk findings.

---

## Problem 4 — Diff two commits and spot the reintroduced secret (60 min)

Simulate a common real-world regression: a secret gets removed in one commit, then accidentally reintroduced in a later "helpful refactor." In a **new, separate** scratch repo (not `leaky-crunch-vault` — keep this isolated so you don't disturb your main lab's clean history):

```bash
mkdir -p ~/c50-week-07/regression-drill && cd ~/c50-week-07/regression-drill
git init -q
echo 'DB_URL = "postgres://user:pass@localhost/db"' > db.py
git add db.py && git commit -q -m "Initial commit"
echo 'DB_URL = os.environ["DB_URL"]' > db.py
git add db.py && git commit -q -m "Fix: load DB_URL from environment"
# Now simulate the regression -- someone "restores" the old version by accident:
echo 'DB_URL = "postgres://user:pass@localhost/db"  # reverted during a merge conflict' > db.py
git add db.py && git commit -q -m "Merge: resolve conflict in db.py"
```

Write `regression-detection.md` describing exactly how you'd catch this **before merge**, not after — specifically, what a pre-commit or pre-push secret scanner would need to check that a one-time repo-wide scan (like Exercise 1's) would miss, since the file *was* clean at some point in history.

**Deliver** `regression-detection.md` plus the three-commit scratch repo (`regression-drill/`).

---

## Problem 5 — Rebuild Crunch Vault from a clean checkout, timed (45 min)

Prove your fixes actually reproduce, not just once while you were building them:

1. Clone your fixed `leaky-crunch-vault` into a fresh directory (or `git worktree add` a clean copy).
2. Time yourself: `git clone`, recreate `.env` from your own notes (never commit it — this step should feel slightly annoying, which is the point), `pip install -r requirements.txt` (create one if you haven't), `python app.py`, and confirm the app comes up and a stored vault entry round-trips correctly.
3. In `rebuild-log.md`, record how long it took, anything that broke on a truly clean checkout, and one thing you'd add to a `SETUP.md` for a new teammate joining this project who has never seen it before.

**Deliver** `rebuild-log.md`. A fix that only works in the directory where you originally wrote it isn't a fix a team can rely on.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 45 min |
| 3 | 45 min |
| 4 | 60 min |
| 5 | 45 min |
| **Total** | **~4 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
