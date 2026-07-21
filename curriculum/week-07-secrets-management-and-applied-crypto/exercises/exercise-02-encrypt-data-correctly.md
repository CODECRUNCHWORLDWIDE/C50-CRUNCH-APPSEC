# Exercise 2 — Encrypt Data Correctly

**Goal:** Replace `homemade_encrypt`/`homemade_decrypt` (repeating-key XOR) and the `crypto_experiments.py` ECB/static-IV code with authenticated encryption from the `cryptography` library, keyed by a properly generated and stored secret — then prove the fix by trying to break the old scheme and failing to break the new one the same way.

**Estimated time:** 90 minutes.

## Before you start

- Exercise 1 is done — `config.py` reads secrets from the environment, not from source.
- `pip install cryptography` succeeded.

## Task 1 — Reproduce the XOR key-reuse break (so you know exactly what you're fixing)

Before touching any code, prove `homemade_encrypt`'s failure to yourself, offline:

```python
from app import homemade_encrypt

key = "crunchkey12345"
ct1 = bytes.fromhex(homemade_encrypt("Transfer $100 to Alice", key))
ct2 = bytes.fromhex(homemade_encrypt("Transfer $900 to Carol!", key))

xored = bytes(a ^ b for a, b in zip(ct1, ct2))
print(xored)   # equals plaintext1 XOR plaintext2 -- the key contributed NOTHING
```

Write one sentence in `exercise-02-notes.md` explaining, in your own words, why this happens whenever the same key encrypts two messages with repeating-key XOR.

## Task 2 — Generate and store a real key correctly

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add the output to your (already-gitignored) `.env`:

```bash
echo "CRUNCH_VAULT_ENC_KEY=<paste the generated key here>" >> .env
```

**Never** hardcode this key as a Python constant — it's a secret exactly like the API key from Exercise 1, and it goes through the same environment-injection path.

## Task 3 — Replace `homemade_encrypt` with `Fernet`

Edit `app.py`:

```python
import os
from cryptography.fernet import Fernet

_fernet = Fernet(os.environ["CRUNCH_VAULT_ENC_KEY"].encode())

def vault_encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()

def vault_decrypt(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()
```

Update the `vault()` route to call `vault_encrypt`/`vault_decrypt` instead of `homemade_encrypt`/`homemade_decrypt`, and delete `make_key_weak()`, `VAULT_KEY`, `homemade_encrypt`, and `homemade_decrypt` entirely — don't leave the broken functions "just in case."

## Task 4 — Prove tamper-detection works (the property XOR never had)

```python
from app import _fernet

token = _fernet.encrypt(b"a real vault secret")
tampered = bytearray(token)
tampered[-5] ^= 0xFF   # flip a bit near the end of the token

try:
    _fernet.decrypt(bytes(tampered))
    print("BUG: tampering was not detected")
except Exception as exc:
    print(f"Tamper correctly detected: {type(exc).__name__}")
```

Run it and confirm you see `Tamper correctly detected: InvalidToken`. Record this result in `exercise-02-notes.md` — it's the single clearest before/after proof of what authenticated encryption buys you over XOR.

## Task 5 — Fix the ECB and static-IV experiments

Edit `crypto_experiments.py`. Replace both broken functions with an `AESGCM`-based one:

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def correct_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)   # fresh, random, every single call
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext

def correct_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
```

Note the return signature changed: the caller must now store the `nonce` **alongside** the ciphertext (it isn't secret, but it's required for decryption, and it must never be reused with the same key).

## Task 6 — Re-run the ECB repetition test against the fix

```python
from crypto_experiments import correct_encrypt
import os

key = os.urandom(32)
plaintext = b"AAAAAAAAAAAAAAAA" + b"BBBBBBBBBBBBBBBB" + b"AAAAAAAAAAAAAAAA"
nonce, ct = correct_encrypt(key, plaintext)

print(ct[0:16] == ct[32:48])   # False now -- GCM's keystream is unique per position, no block repeats
```

## Task 7 — Log the finding as fixed

```sql
INSERT INTO secret_findings (location, secret_type, matched_snippet, status, remediated_at)
VALUES ('app.py: homemade_encrypt', 'homemade_crypto', 'XOR cipher (removed)', 'purged', CURRENT_TIMESTAMP);

INSERT INTO secret_findings (location, secret_type, matched_snippet, status, remediated_at)
VALUES ('crypto_experiments.py', 'broken_crypto_mode', 'ECB + static IV (removed)', 'purged', CURRENT_TIMESTAMP);
```

## Expected result (spot checks)

- `homemade_encrypt`, `homemade_decrypt`, `make_key_weak`, and `VAULT_KEY` no longer exist anywhere in `app.py`.
- Storing a secret through the running app (`python app.py`, then submit the form at `http://127.0.0.1:5050/`) round-trips correctly through `Fernet` — what you type back out matches what you typed in.
- The tamper test from Task 4 raises `InvalidToken`.
- The ECB repetition test from Task 6 prints `False`.

## Done when…

- [ ] All vault storage uses `Fernet` (or `AESGCM`), never the deleted XOR functions.
- [ ] The encryption key comes from `os.environ`, generated with `Fernet.generate_key()`, never hardcoded.
- [ ] `exercise-02-notes.md` documents both the XOR-key-reuse break (Task 1) and the tamper-detection proof (Task 4) in your own words.
- [ ] `crypto_experiments.py`'s ECB and static-IV functions are replaced with `AESGCM`, and the repetition test confirms the fix.
- [ ] `week07.db` has findings rows for both the XOR cipher and the ECB/static-IV code, marked `purged`.

## Stretch

- Add `associated_data` to your `AESGCM` calls — authenticate the vault entry's `label` alongside its encrypted `secret`, so a label can't be swapped onto a different ciphertext even though it's stored unencrypted. Confirm decryption fails if the label is tampered with.
- Benchmark `Fernet` vs. raw `AESGCM` for 10,000 encrypt/decrypt round-trips and note the difference — useful context for why some high-throughput services reach for `AESGCM` directly instead of `Fernet`'s extra framing.

## Submission

Commit your updated `app.py`, `crypto_experiments.py`, `exercise-02-notes.md`, and the extended `week07.db` to your portfolio under `c50-week-07/exercise-02/`.
