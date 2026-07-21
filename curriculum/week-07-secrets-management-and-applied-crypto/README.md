# Week 7 — Secrets Management & Applied Crypto

> **Goal:** by Sunday you can find every hardcoded secret in a codebase — including the ones "removed" but still sitting in git history — replace them with a managed/injected store that supports rotation, and look at any piece of code that hashes, encrypts, or signs something and say precisely whether it's using a vetted primitive correctly or quietly broken.

Welcome back to **C50 · Crunch AppSec**. Week 3 named "Cryptographic Failures" as an OWASP Top 10 risk category and showed you what it looks like from the outside. This week you go inside it: you'll leak your own secrets on purpose, find them the way an attacker (or a scanner) would, and then fix the two failure modes that show up in almost every real breach report — **secrets sitting in plaintext somewhere they shouldn't be**, and **crypto that was rolled by hand instead of reached for from a vetted library**. Both failures share a root cause: someone treated "it looks encrypted" or "it's not in the README" as good enough. This week you'll stop taking that on faith and start proving it — with a scanner, a database of findings, and code you can point to.

The two halves of the week connect. A secrets vault is only as good as the encryption protecting it at rest and the transport carrying it in flight — so after you learn *where* secrets leak and *how* to manage them, you spend the second half learning the cryptographic primitives well enough to build (and fix) that protection yourself: hashing, symmetric and asymmetric encryption, and digital signatures, plus the specific mistakes — ECB mode, a reused IV, a non-cryptographic RNG, a homemade cipher — that turn "encrypted" into "obfuscated."

> **Ethics & legality — binding, every week.** Everything below is **authorized, legal, defensive-minded** security work performed **only inside the isolated lab you own** — a local git repository and a small Flask + SQLite app you run yourself on `127.0.0.1`. Every "secret" in this week's lab is a **fake, clearly-labeled placeholder value** (`sk_live_REDACTED-EXAMPLE-not-a-real-key...`, `AKIAIOSFODNN7EXAMPLE`, and similar) — never enter a real credential into any lab file. The scanning techniques you practice (regex secret hunting, `git log -p`, history search) are taught so you can run them defensively against **your own repositories**, in CI, and with written authorization, against your employer's — never against a repository you don't own or have explicit permission to scan. Reverse-engineering a broken cipher happens entirely on data you generated yourself, offline, with no network calls involved.

## Learning objectives

By the end of this week, you will be able to:

- **Find** hardcoded secrets across source, config, environment files, logs, and git history — including secrets that were "removed" in a later commit but still live in the repo's history.
- **Manage** secrets correctly: environment injection for local dev, a vault or secrets manager for CI/production, and a rotation plan that assumes any leaked secret is compromised the moment it leaks, not the moment someone proves it was used.
- **Choose the right cryptographic primitive** for a job — hashing for integrity/no-key checks, symmetric encryption for confidentiality with a shared key, asymmetric encryption/signing for identity and non-repudiation — and explain why the three are not interchangeable.
- **Use vetted libraries correctly** and name the specific mistakes that break homemade or misused crypto: ECB mode, a static or reused IV/nonce, a non-cryptographic RNG for keys or tokens, and non-constant-time comparisons for secrets.
- **Store secret-scanning findings and remediation status in a database** (SQLite via Python) — every finding is a row, every fix is a status change, and "done" means the database says so, not a memory of having fixed it.

## Prerequisites

- **Weeks 1–6 completed.** Specifically: your isolated lab is up (Week 1), you can name a trust boundary (Week 2), you know A02:2021 Cryptographic Failures and A05:2021 Security Misconfiguration by name (Week 3), you've hardened password storage with a KDF (Week 4) — which is itself a hashing primitive, so this week extends that vocabulary rather than starting over — and you've fixed injection and access-control bugs (Weeks 5–6) in code that, this week, turns out to *also* have hardcoded secrets sitting in it. Real apps stack flaws; this week's lab is no exception.
- Python 3.10+, `pip`, and `git`. `sqlite3` and `hmac`/`hashlib` ship with Python.
- Install the `cryptography` package (vetted, widely-used, the one this week standardizes on): `pip install cryptography flask`.
- [C33 Crunch SQL](../../../C33-CRUNCH-SQL/) helps for the findings-database work but isn't required — the SQL you need is explained from scratch.

## This week's target: Crunch Vault

This week's lab has two connected pieces you build once, on Monday, and use all week: a **leaky git repository** (for finding secrets) and **Crunch Vault**, a tiny Flask + SQLite app that is supposed to store secrets safely and, on purpose, doesn't yet.

```mermaid
flowchart LR
  dev["You (127.0.0.1 only)"] --> repo["leaky-crunch-vault/\ngit repo w/ secrets in history"]
  dev --> app["Crunch Vault\napp.py — Flask on :5050"]
  app --> db[("SQLite\ncrunch_vault.db")]
  app --> log["app.log\n(leaks secrets in plaintext)"]
  dev --> findings[("SQLite\nsecret_findings.db")]
  dev -. scans .-> repo
  findings -. tracked by .-> dev
```

### Set up the lab (do this first)

```bash
mkdir -p ~/c50-week-07/leaky-crunch-vault && cd ~/c50-week-07/leaky-crunch-vault
git init -q
python3 -m venv venv && source venv/bin/activate
pip install flask cryptography
```

**Step 1 — commit the app with a hardcoded secret already in it (VULN #1).**

Save this as `config.py`:

```python
# config.py -- VULN #1: hardcoded secrets in source. Anyone who can read this
# file, or clone this repo, has the API key, the DB password, and the
# session-signing secret. Real incident reports name this as a top cause of
# breach. See Lecture 1 Sec 1, fixed in Exercise 1.
API_KEY = "sk_live_REDACTED-EXAMPLE-not-a-real-key"
DB_PASSWORD = "Vault_Admin_2024!"
FLASK_SECRET_KEY = "change-me-super-secret"
```

Save this as `app.py` — the Crunch Vault app itself:

```python
#!/usr/bin/env python3
"""
Crunch Vault -- a DELIBERATELY broken Flask + SQLite "secrets vault" for C50
Week 7. It exists to teach you to find leaked secrets and broken crypto --
NOT to store anything real. Run ONLY on 127.0.0.1, inside your own isolated
lab. Never deploy this code or point any technique here at a system you
don't own. Every fake secret here is a clearly-labeled placeholder.
"""
import hashlib
import hmac
import logging
import os
import random
import sqlite3

from flask import Flask, g, render_template_string, request

from config import API_KEY, DB_PASSWORD, FLASK_SECRET_KEY  # VULN #1, see above

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
DB_PATH = "crunch_vault.db"

# VULN #3 -- secrets in logs. Every value passed to this app.log gets
# written to disk in plaintext, forever, and usually ends up shipped to a
# log aggregator with looser access controls than the app itself.
# See Lecture 1 Sec 1, Exercise 1.
logging.basicConfig(filename="app.log", level=logging.INFO)
log = logging.getLogger("crunch-vault")


# ---------------------------------------------------------------------------
# VULN #5 -- weak RNG. random.random()/random.randint() are Mersenne
# Twister output: fast, deterministic given the seed, and NOT
# cryptographically secure. Never use the `random` module for keys, tokens,
# or nonces. See Lecture 3 Sec 2, Exercise 2, Challenge 1.
# ---------------------------------------------------------------------------
def make_key_weak() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(16))


VAULT_KEY = make_key_weak()  # a "key" for the homemade cipher below


# ---------------------------------------------------------------------------
# VULN #4 -- homemade crypto. A repeating-key XOR is not encryption: it has
# no authentication (nothing detects tampering) and reusing the key across
# messages makes it breakable via a two-ciphertext XOR (crib-dragging), no
# secret needed. See Lecture 2 Sec 1, Lecture 3 Sec 1, Exercise 2.
# ---------------------------------------------------------------------------
def homemade_encrypt(plaintext: str, key: str) -> str:
    data = plaintext.encode()
    key_bytes = key.encode()
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return out.hex()


def homemade_decrypt(ciphertext_hex: str, key: str) -> str:
    data = bytes.fromhex(ciphertext_hex)
    key_bytes = key.encode()
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return out.decode(errors="replace")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS vault_entries;
        CREATE TABLE vault_entries (
            id         INTEGER PRIMARY KEY,
            label      TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    db.commit()
    db.close()


STORE_FORM = """
<h1>Crunch Vault (deliberately broken lab app)</h1>
<form method="post">
  Label: <input name="label"><br>
  Secret: <input name="secret"><br>
  <button type="submit">Store</button>
</form>
<ul>{% for e in entries %}<li>{{ e['label'] }}: {{ e['ciphertext'] }}</li>{% endfor %}</ul>
"""


@app.route("/", methods=["GET", "POST"])
def vault():
    db = get_db()
    if request.method == "POST":
        label = request.form.get("label", "")
        secret = request.form.get("secret", "")
        # VULN #3 (cont'd) -- the secret being stored is ALSO logged in
        # plaintext right here, defeating the entire point of a vault.
        log.info("Storing secret label=%s value=%s", label, secret)
        ciphertext = homemade_encrypt(secret, VAULT_KEY)
        db.execute(
            "INSERT INTO vault_entries (label, ciphertext) VALUES (?, ?)",
            (label, ciphertext),
        )
        db.commit()
    entries = db.execute("SELECT * FROM vault_entries ORDER BY id DESC").fetchall()
    return render_template_string(STORE_FORM, entries=entries)


# ---------------------------------------------------------------------------
# VULN #8 -- naive signature check. `==` on secret-derived strings is NOT
# constant-time in CPython: it returns as soon as it finds a mismatched
# byte, so response timing leaks how many leading bytes were correct. A
# patient network attacker can recover a valid signature one byte at a
# time. See Lecture 2 Sec 3, Exercise 3.
# ---------------------------------------------------------------------------
@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    expected = hmac.new(API_KEY.encode(), payload, hashlib.sha256).hexdigest()
    given = request.headers.get("X-Signature", "")
    if given == expected:  # VULN #8: should be hmac.compare_digest(given, expected)
        return {"status": "verified"}
    return {"status": "rejected"}, 400


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
```

Save this as `crypto_experiments.py` — two "upgrades" that are still broken, used in Lecture 3 and Exercise 2:

```python
#!/usr/bin/env python3
"""crypto_experiments.py -- run this OFFLINE, inside the isolated lab only.
Two attempts to do better than XOR. Both are still broken. See Lecture 3."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(16))  # VULN #7 (partial) -- fine as a key, watch the IV below


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def broken_ecb_encrypt(plaintext: bytes) -> bytes:
    # VULN #6 -- ECB mode encrypts each 16-byte block independently with
    # the SAME key and no chaining between blocks. Identical plaintext
    # blocks always produce identical ciphertext blocks, so structure and
    # repetition in the plaintext leak straight through the "encryption."
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()


STATIC_IV = b"\x00" * 16  # VULN #7 -- the SAME iv, every single call


def broken_cbc_encrypt(plaintext: bytes) -> bytes:
    # CBC chains blocks together, which fixes ECB's pattern leak -- but
    # reusing the IV across messages reintroduces a related failure: two
    # messages with the same first block produce the same first
    # ciphertext block, and an attacker who can influence plaintext can
    # sometimes recover the IV/key relationship entirely.
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(STATIC_IV))
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
```

Now commit the app, then walk straight into the git-history mistake this week is built around:

```bash
git add config.py app.py crypto_experiments.py
git commit -q -m "Initial commit: Crunch Vault MVP"

# A second, "real-looking" secret gets added in a .env -- a classic move
# for local dev convenience that skips code review entirely.
cat > .env <<'EOF'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_REDACTED-EXAMPLE-not-a-real-key
EOF
git add .env
git commit -q -m "Add environment config for local dev"

# "Fixed" a week later -- .env is removed and gitignored. The team believes
# the secret is gone. It is NOT: it is still readable in commit history.
git rm -q .env
echo ".env" >> .gitignore
git add .gitignore
git commit -q -m "Remove .env from repo, add to gitignore"
```

Confirm the app runs:

```bash
python app.py
# in another terminal:
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5050/   # expect: 200
```

And confirm the "fixed" secret is, in fact, still there (this is exactly what Exercise 1 automates):

```bash
git log -p --all -- .env | grep -c "AKIA"   # expect: a nonzero count
```

Eight deliberate vulnerabilities are numbered directly in the comments and the commands above. You'll reference these numbers all week — write them down now:

| # | Where | Flaw | Fixed in |
|---|-------|------|----------|
| 1 | `config.py` | Hardcoded API key, DB password, Flask secret key in source | Exercise 1 |
| 2 | git history (`.env`) | "Removed" secret still recoverable via `git log -p` | Exercise 1 |
| 3 | `app.py` / `app.log` | Secrets logged in plaintext on every request | Exercise 1 |
| 4 | `app.py: homemade_encrypt` | Homemade repeating-key XOR "encryption" | Exercise 2 |
| 5 | `app.py: make_key_weak` | Non-cryptographic RNG (`random`) used for a key | Exercise 2, Challenge 1 |
| 6 | `crypto_experiments.py: broken_ecb_encrypt` | AES in ECB mode — pattern leakage | Lecture 3, Challenge 1 |
| 7 | `crypto_experiments.py: broken_cbc_encrypt` | Static/reused IV in AES-CBC | Lecture 3, Challenge 1 |
| 8 | `app.py: webhook()` | Non-constant-time signature comparison (`==`) | Exercise 3 |

## This week's map

Work top to bottom. Each piece assumes the ones before it.

| # | File | What's inside | ~Time |
|--:|------|---------------|------:|
| 1 | [lecture-notes/01-where-secrets-leak.md](./lecture-notes/01-where-secrets-leak.md) | Secrets in source, config, env, logs, and git history; scanning; the vault + rotation model | 2h |
| 2 | [lecture-notes/02-crypto-primitives-for-developers.md](./lecture-notes/02-crypto-primitives-for-developers.md) | Hash vs. encryption vs. signing; symmetric vs. asymmetric; key management; picking the right tool | 2h |
| 3 | [lecture-notes/03-crypto-failures-and-how-to-avoid-them.md](./lecture-notes/03-crypto-failures-and-how-to-avoid-them.md) | ECB, static IVs, weak RNG, and homemade schemes — shown broken, then fixed with vetted APIs | 2h |
| 4 | [exercises/exercise-01-scan-and-purge-secrets.md](./exercises/exercise-01-scan-and-purge-secrets.md) | Scan the lab repo, log findings in SQLite, purge history, rotate, and re-verify | 1.5h |
| 5 | [exercises/exercise-02-encrypt-data-correctly.md](./exercises/exercise-02-encrypt-data-correctly.md) | Replace XOR/ECB/static-IV with authenticated encryption (Fernet / AES-GCM) | 1.5h |
| 6 | [exercises/exercise-03-sign-and-verify.md](./exercises/exercise-03-sign-and-verify.md) | Fix the webhook's timing-unsafe check; add HMAC and Ed25519 signing | 1h |
| 7 | [challenges/challenge-01-fix-a-broken-crypto-feature.md](./challenges/challenge-01-fix-a-broken-crypto-feature.md) | Fix a password-reset-token feature that stacks weak RNG + homemade crypto | 2h |
| 8 | [challenges/challenge-02-design-a-secrets-workflow.md](./challenges/challenge-02-design-a-secrets-workflow.md) | Design and implement a full dev → CI → prod secrets workflow with rotation | 2h |
| 9 | [mini-project/README.md](./mini-project/README.md) | Purge secrets, rotate them, fix all the crypto, track every finding in a database | 3h |
| 10 | [homework.md](./homework.md) | Extra practice, spread across the week | 4h |
| 11 | [quiz.md](./quiz.md) | 15 self-check questions + answer key | 1h |
| 12 | [resources.md](./resources.md) | OWASP cheat sheets, official docs, the few links worth your time | — |

## Weekly schedule

Adds up to roughly **~24 hours**. Treat it as a target, not a stopwatch.

| Day | Focus | Lectures | Exercises | Challenges | Quiz/Read | Homework | Mini-Project | Daily Total |
|-----------|--------------------------------------------------|---------:|----------:|-----------:|----------:|---------:|-------------:|------------:|
| Monday | Set up the lab; where secrets leak | 2h | 0h | 0h | 0.5h | 1h | 0h | 3.5h |
| Tuesday | Secret scanning + git history; purge & rotate | 0h | 1.5h | 0h | 0.5h | 1h | 0h | 3h |
| Wednesday | Crypto primitives; encrypt data correctly | 2h | 1.5h | 0h | 0.5h | 1h | 0h | 5h |
| Thursday | Crypto failures; sign & verify | 2h | 1h | 0h | 0.5h | 1h | 0.5h | 5h |
| Friday | Broken-feature + secrets-workflow challenges | 0h | 0h | 4h | 0.5h | 1h | 0.5h | 6h |
| Saturday | Mini-project | 0h | 0h | 0h | 0h | 0h | 2h | 2h |
| Sunday | Quiz + review | 0h | 0h | 0h | 1h | 0h | 0h | 1h |
| **Total** | | **6h** | **4h** | **4h** | **3.5h** | **4h** | **3h** | **~24.5h** |

## By the end of this week you can…

- Find a hardcoded secret in source, in a config file, in a log line, and in a commit that "removed" it three commits ago — and know the difference between hiding a secret and rotating it.
- Explain, without hedging, why purging a secret from git history is necessary but not sufficient: if it was ever pushed, you must treat it as compromised and rotate it.
- Look at a block of crypto code and say, correctly, whether it's hashing, encrypting, or signing — and why swapping one for another is a bug, not a style choice.
- Name ECB mode, a reused IV, a non-cryptographic RNG, and a non-constant-time comparison on sight, in any language, and fix each one with the vetted-library equivalent.
- Query a findings database and answer "how many secrets are still unrotated?" or "which crypto findings are fixed?" with a `SELECT`, not a guess.

## Up next

[Week 8 — SAST, DAST & SCA tooling](../week-08-sast-dast-and-sca-tooling/) — this week you found flaws by hand; next week you wire up the scanners that find them automatically, on every commit, so the vulnerability classes from Weeks 3–7 get caught before they ship.

---

*Part of the Code Crunch Worldwide open curriculum · GPL-3.0 · If you find errors, please open an issue or PR.*
