# Mini-Project — Purge Secrets, Fix Crypto, Prove It in a Database

> Take Crunch Vault from "leaks secrets in four places and encrypts nothing correctly" to "every secret is managed and rotated, every cryptographic primitive is vetted and authenticated" — and back every claim with a query against a findings database, not a memory of having fixed things.

**Estimated time:** 3 hours, best done Saturday after the exercises and challenges.

This is the week's capstone: the same lab, `leaky-crunch-vault`, taken from its README-setup broken state all the way to a version you could actually defend in a security review. Every fix this week — the exercises, the challenges — touched one piece. This mini-project asks you to confirm all of them are done, together, against one coherent database, with a report that proves it.

---

## Deliverable

A directory in your portfolio `c50-week-07/mini-project/` containing:

1. `leaky-crunch-vault/` — the fully-fixed lab: no hardcoded secrets, no secret-leaking logs, no XOR/ECB/static-IV crypto anywhere, `hmac.compare_digest` on the webhook, and a purged, clean git history.
2. `week07.db` — your SQLite database with a complete `secret_findings` table covering every flaw this week introduced, each with an accurate `status`.
3. `payload_tests.db` (or a `payload_results` table in `week07.db`) — a payload library proving your fixes hold, per Part 3 below.
4. `report.md` — a written summary tying it together (structure specified below).

---

## Requirements

### Part 1 — Secrets: gone from source, gone from history, rotated

- `config.py` (and anywhere else a secret used to live) reads every value from `os.environ`. `grep -rniE "(api[_-]?key|secret|password)\s*=\s*['\"]" --include="*.py" .` on the fixed repo returns **zero matches for actual values** (matches on `os.environ[...]` lines are fine — those reference a *name*, not a value).
- `git log --all --oneline -- .env` returns **nothing** — history is purged, confirmed the same way Exercise 1 confirmed it.
- Every secret that was ever committed has a corresponding row in `secret_findings` with `status = 'rotated'` **and** a fresh (still-fake) value in the current `.env` — rotation isn't optional cleanup, it's the actual fix.
- A pre-commit scanner (`detect-secrets` or `gitleaks`) is installed and its baseline is committed.

### Part 2 — Crypto: every primitive vetted, every mode authenticated

- No `homemade_encrypt`/`homemade_decrypt`, no `AES.MODE_ECB`, no static IV, and no `random.random()`/`random.randint()` anywhere in the fixed lab's code — confirm with a grep pass and list what you searched for in `report.md`.
- Vault entries are encrypted with `Fernet` or `AESGCM`, keyed by a value generated with a CSPRNG and loaded from the environment.
- `/webhook` uses `hmac.compare_digest`.
- At least one signing flow (HMAC or Ed25519, from Exercise 3) is wired into a real route or CLI tool, not left as a standalone script nobody calls.

### Part 3 — Prove it with a payload library

Build `verify_fixes.py`: a script that re-runs a small library of "attacks" against the **fixed** code and records pass/fail as data.

```python
PAYLOAD_LIBRARY = [
    {"id": "xor-key-reuse", "description": "Two encryptions of different plaintext with the same key should NOT allow XOR recovery"},
    {"id": "ecb-block-repeat", "description": "Repeated plaintext blocks should NOT produce repeated ciphertext blocks"},
    {"id": "tamper-detection", "description": "A single flipped bit in stored ciphertext should raise on decrypt, not decrypt silently"},
    {"id": "weak-rng-repeat", "description": "1,000 generated tokens/keys should show no repeats and no obvious digit bias"},
    {"id": "timing-safe-compare", "description": "hmac.compare_digest is used for every secret-derived comparison in the codebase"},
    {"id": "no-secrets-in-source", "description": "No literal secret value appears in any tracked file"},
    {"id": "no-secrets-in-history", "description": "git log -p --all shows no leaked secret pattern anywhere in history"},
]
```

For each entry, write the actual check (most of these are direct re-runs of code from the exercises and challenges), record a `PASS`/`FAIL` row into a `payload_results` table (`id`, `description`, `result`, `checked_at`), and print a summary table. **Every row must say `PASS`** before you submit — a `FAIL` here means a fix from earlier this week regressed or was never completed.

### Part 4 — `report.md`

Write a report covering:

1. **Executive summary** (~150 words) — for a non-technical stakeholder: what was wrong with Crunch Vault, what "fixed" concretely means now, and what would have happened if this had shipped as-is (tie to a real consequence: a leaked payment key, a decryptable vault, a forgeable webhook).
2. **Findings table** — pulled from `SELECT location, secret_type, status FROM secret_findings ORDER BY status;` — every row, not a curated subset.
3. **Payload results table** — pulled from `verify_fixes.py`'s `payload_results` table, all seven checks, all `PASS`.
4. **One thing that surprised you** — of everything you fixed this week, which flaw's *actual exploit* (not just "this is bad practice") was more or less severe than you expected before you tried it, and why?
5. **Reflection** (~150 words): Which was harder — finding the secrets, or fixing the crypto? Where did "looks fine" almost fool you before you actually tested it?

---

## Milestones

- **Milestone 1 (45 min):** Confirm Exercises 1–3 and both challenges are actually complete and merged into one working `leaky-crunch-vault/` — not scattered across separate exercise branches.
- **Milestone 2 (45 min):** Run the Part 1/2 grep and git-history checks; fix anything that slipped through.
- **Milestone 3 (60 min):** Write and run `verify_fixes.py`; get all seven payload checks to `PASS`.
- **Milestone 4 (30 min):** Write `report.md`, pull both required tables from live queries, proofread the executive summary.

---

## Rubric

| Criterion | Weight | "Great" looks like |
|-----------|------:|--------------------|
| Secrets fully remediated | 25% | Zero literal secrets in source or history; every leaked secret rotated, not just purged |
| Crypto fully remediated | 25% | Zero homemade/ECB/static-IV/weak-RNG code remains; authenticated encryption and constant-time comparison used throughout |
| Payload library rigor | 25% | All 7 checks implemented for real (not stubbed `True`) and all passing against the actual fixed code |
| Report clarity | 15% | Executive summary is readable by a non-technical stakeholder; both tables come from real queries |
| Reflection honesty | 10% | Names a genuine surprise or near-miss, not a generic "I learned a lot" |

---

## Why this matters

Secrets management and applied crypto are the two areas of AppSec where "looks fine" is most dangerous — broken crypto still produces ciphertext-shaped output, and a leaked secret causes no visible symptom until it's used against you. This mini-project's whole structure — grep for it, purge it, prove it with a repeatable check, record the result in a queryable table — is the discipline that scales past one lab app: it's the same loop a real secrets-scanning pipeline (Week 8's SAST/DAST/SCA tooling) runs automatically, on every commit, for the rest of a codebase's life.

When done: push your work, then take the [quiz](../quiz.md) and start [Week 8 — SAST, DAST & SCA tooling](../../week-08-sast-dast-and-sca-tooling/).
