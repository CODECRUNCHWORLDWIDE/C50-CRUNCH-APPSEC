# Week 7 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **Python 3.10+** — `sqlite3`, `hashlib`, and `hmac` ship with it: <https://www.python.org/downloads/>.
- **`cryptography`** — this week's vetted crypto library, used throughout: `pip install cryptography`. Docs: <https://cryptography.io/en/latest/>.
- **Flask** — runs Crunch Vault: `pip install flask`.
- **`git-filter-repo`** — the currently-recommended tool for rewriting git history: `pip install git-filter-repo`. Docs: <https://github.com/newren/git-filter-repo>.
- **`detect-secrets`** (Yelp) — pre-commit secret scanner used in Exercise 1: `pip install detect-secrets`. Docs: <https://github.com/Yelp/detect-secrets>.
- **gitleaks** (optional, stretch goals) — a second scanner to cross-check your own regex sweep: <https://github.com/gitleaks/gitleaks>.

## Required reading (this week's core)

- **OWASP Secrets Management Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
  *Why: the canonical vault/injection/rotation model Lecture 1 is built on.*
- **OWASP Cryptographic Storage Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
  *Why: algorithm-selection guidance behind Lectures 2 and 3 — which primitives are currently considered vetted and why.*
- **`cryptography` library docs — Fernet:** <https://cryptography.io/en/latest/fernet/>
  *Why: the exact API Exercise 2 uses to replace the homemade XOR cipher.*
- **`cryptography` library docs — AEAD (AES-GCM):** <https://cryptography.io/en/latest/hazmat/primitives/aead/>
  *Why: lower-level authenticated encryption, used in Exercise 2's `crypto_experiments.py` fix.*
- **Python `hmac` module docs, especially `compare_digest`:** <https://docs.python.org/3/library/hmac.html>
  *Why: the exact fix for this week's `/webhook` timing-unsafe comparison.*
- **NIST SP 800-38A — Block cipher modes of operation:** <https://csrc.nist.gov/pubs/sp/800/38/a/final>
  *Why: the formal government-standard treatment of ECB/CBC/GCM behind Lecture 3's demonstrations.*
- **GitHub — Removing sensitive data from a repository:** <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
  *Why: the official walkthrough for exactly what Exercise 1's history-purge does and why rotation still matters afterward.*

## Reference (keep in tabs)

- **Python `secrets` module:** <https://docs.python.org/3/library/secrets.html>
- **`cryptography` library — Ed25519:** <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/>
- **NIST SP 800-57 Part 1 — Key Management Recommendations:** <https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final>
- **HashiCorp Vault — What is Vault?** (product docs, useful context for Challenge 2's design): <https://developer.hashicorp.com/vault/docs/what-is-vault>
- **GitHub Actions — Encrypted secrets:** <https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions>
- **SQLite — `CHECK` constraints** (used for the `secret_findings.status` column): <https://www.sqlite.org/lang_createtable.html#ckconst>
- **Python `sqlite3` module docs:** <https://docs.python.org/3/library/sqlite3.html>

## Practice beyond this week's lab

- **"The ECB Penguin"** (a widely-cited visual demonstration of ECB's pattern leakage): <https://words.filippo.io/the-ecb-penguin/>
- **CyberChef** (browser-based tool for experimenting with encodings, hashes, and simple ciphers — useful for exploring the XOR-key-reuse math from Lecture 3 by hand): <https://gchq.github.io/CyberChef/>
- **gitleaks — README examples**, for seeing what a real scanner's ruleset looks like beyond this week's hand-rolled regex: <https://github.com/gitleaks/gitleaks#readme>

## Deeper background (optional this week)

- **Verizon Data Breach Investigations Report (DBIR, annual, free):** <https://www.verizon.com/business/resources/reports/dbir/>
  *Why: credential/secret exposure shows up as a leading breach vector year after year — read the section on credentials.*
- **NIST — Recommendation for Key Management (SP 800-57, full series):** <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
  *Why: the full depth behind this week's condensed key-management rules, for anyone designing a production key-management system.*

## Glossary

| Term | Definition |
|------|------------|
| **Secret** | Any value that grants access if disclosed — API key, password, signing key, private key. |
| **Secret sprawl** | Secrets scattered across source, config, env files, logs, and history instead of one managed system of record. |
| **Vault / secrets manager** | A dedicated, access-controlled, audit-logged system of record for secrets, separate from source control. |
| **Environment injection** | Populating an app's environment with secret values at runtime, so source code never contains them. |
| **Rotation** | Issuing a new credential and retiring the old one on a defined cadence, or immediately after any suspected exposure. |
| **Hash** | A one-way, keyless function producing a fixed-size digest, used for integrity checks (SHA-256) or password storage (bcrypt/Argon2 — a different sub-category). |
| **Symmetric encryption** | Encryption using one shared key for both encrypting and decrypting (AES). |
| **Asymmetric encryption** | Encryption using a public/private key pair — encrypt with the public key, decrypt only with the private key. |
| **Signature** | A private-key-produced proof of authorship and integrity, verifiable by anyone with the matching public key. |
| **HMAC** | A keyed hash providing shared-secret message authentication — the symmetric-key equivalent of a signature. |
| **AEAD** | Authenticated Encryption with Associated Data — an encryption mode (e.g., AES-GCM) that also detects tampering. |
| **ECB mode** | A block-cipher mode that encrypts each block independently, leaking plaintext structure through repeated ciphertext blocks. |
| **IV / nonce** | A per-encryption value required by many cipher modes; must be unique (and for some modes, random) every single time. |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator — required for keys, tokens, and nonces (`os.urandom`, `secrets`); `random` is not one. |
| **Constant-time comparison** | A comparison whose execution time doesn't depend on where two values differ, preventing timing side-channel attacks (`hmac.compare_digest`). |
| **Findings store** | A structured, queryable record of security findings (SQL/Python) — never a spreadsheet. |

---

*Broken link? Open an issue or PR.*
