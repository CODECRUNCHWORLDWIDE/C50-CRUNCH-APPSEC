# Exercise 3 — Sign and Verify

**Goal:** Fix the `/webhook` route's timing-unsafe signature comparison, then implement both an HMAC (shared-secret) and an Ed25519 (asymmetric) sign/verify flow, so you've built the same "prove who sent this, unaltered" guarantee both ways this course teaches it.

**Estimated time:** 60 minutes.

## Before you start

- Exercises 1–2 are done — secrets come from the environment, and vault storage uses `Fernet`.
- Crunch Vault is running (`python app.py`) so you can hit `/webhook` with `curl`.

## Task 1 — Demonstrate the timing gap exists (conceptually)

Read the current `/webhook` route:

```python
@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    expected = hmac.new(API_KEY.encode(), payload, hashlib.sha256).hexdigest()
    given = request.headers.get("X-Signature", "")
    if given == expected:   # VULN #8
        return {"status": "verified"}
    return {"status": "rejected"}, 400
```

In `exercise-03-notes.md`, write two or three sentences explaining exactly why `given == expected` is unsafe: Python's string equality short-circuits at the first mismatched character, so a byte-by-byte timing difference exists between "wrong in the first character" and "wrong in the last character" — a difference an attacker with enough network samples can use to guess a valid signature one byte at a time, entirely without ever seeing `API_KEY`.

## Task 2 — Fix it with `hmac.compare_digest`

```python
@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    expected = hmac.new(API_KEY.encode(), payload, hashlib.sha256).hexdigest()
    given = request.headers.get("X-Signature", "")
    if hmac.compare_digest(given, expected):   # constant-time, regardless of where they differ
        return {"status": "verified"}
    return {"status": "rejected"}, 400
```

Verify it still accepts a correctly-signed request:

```bash
API_KEY="$(python -c "from config import API_KEY; print(API_KEY)")"
BODY='{"event":"vault.entry.created"}'
SIG=$(python -c "
import hmac, hashlib, os
print(hmac.new(os.environ['K'].encode(), b'$BODY', hashlib.sha256).hexdigest())
" K="$API_KEY")

curl -s -X POST http://127.0.0.1:5050/webhook \
  -H "X-Signature: $SIG" -d "$BODY"
# expect: {"status":"verified"}

curl -s -X POST http://127.0.0.1:5050/webhook \
  -H "X-Signature: 0000000000000000000000000000000000000000000000000000000000000000" \
  -d "$BODY"
# expect: {"status":"rejected"} with a 400
```

## Task 3 — Build a standalone HMAC signer/verifier

Create `sign_hmac.py` — a reusable module, separate from the Flask app, for signing arbitrary payloads with a shared secret:

```python
#!/usr/bin/env python3
import hashlib
import hmac

def sign(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify(secret: bytes, payload: bytes, signature: str) -> bool:
    expected = sign(secret, payload)
    return hmac.compare_digest(signature, expected)

if __name__ == "__main__":
    secret = b"a-shared-signing-key-from-the-vault"
    payload = b'{"event": "vault.entry.created", "label": "db-password"}'

    signature = sign(secret, payload)
    print(f"Signature: {signature}")
    print(f"Valid signature check: {verify(secret, payload, signature)}")          # True
    print(f"Tampered payload check: {verify(secret, payload + b'!', signature)}")  # False
```

Run it and confirm both checks print the expected `True`/`False`.

## Task 4 — Build an Ed25519 signer/verifier

Create `sign_ed25519.py` — the asymmetric equivalent, for cases where the verifier shouldn't need to know a shared secret, only a public key:

```python
#!/usr/bin/env python3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def sign(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload)

def verify(public_key, payload: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False

if __name__ == "__main__":
    private_key, public_key = generate_keypair()
    payload = b'{"event": "vault.entry.created", "label": "db-password"}'

    signature = sign(private_key, payload)
    print(f"Valid signature check: {verify(public_key, payload, signature)}")            # True
    print(f"Tampered payload check: {verify(public_key, payload + b'!', signature)}")     # False

    # Serialize the public key the way you'd actually distribute it -- to
    # whoever needs to verify signatures, without ever handing them the
    # private key.
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(f"Public key ({len(public_bytes)} bytes): {public_bytes.hex()}")
```

## Task 5 — Write down which one you'd use, and why

In `exercise-03-notes.md`, answer in 3-4 sentences: for Crunch Vault's `/webhook` route specifically, both the sender and Crunch Vault already share `API_KEY` — is HMAC or Ed25519 the better fit here, and would your answer change if a *third party* (not Crunch Vault itself) needed to send signed webhook payloads without ever being trusted with the vault's own secrets?

## Expected result (spot checks)

- The `curl` commands in Task 2 return `verified` for a correctly-signed request and `rejected`/400 for a bad signature.
- `sign_hmac.py` prints `True` then `False` for the valid/tampered checks.
- `sign_ed25519.py` prints `True` then `False`, and prints a 32-byte public key in hex.

## Done when…

- [ ] `/webhook` uses `hmac.compare_digest`, not `==`, and both `curl` checks behave as expected.
- [ ] `sign_hmac.py` and `sign_ed25519.py` both exist, run standalone, and correctly detect tampering.
- [ ] `exercise-03-notes.md` explains the timing-attack mechanism (Task 1) and the HMAC-vs-Ed25519 tradeoff (Task 5) in your own words.
- [ ] `week07.db` has a finding row for the `/webhook` comparison bug, marked `purged`.

## Stretch

- Time 1,000 calls to `given == expected` vs. `hmac.compare_digest(given, expected)` for strings that differ in their first character vs. their last character. The `==` version should show a measurable timing difference; `compare_digest` should not (within noise).
- Add a `nonce` and `timestamp` to the HMAC-signed payload in `sign_hmac.py`, and reject any request whose timestamp is more than 5 minutes old — this defeats a **replay attack** (an attacker resending a previously valid, correctly-signed request), which HMAC alone does not protect against.

## Submission

Commit your updated `app.py`, `sign_hmac.py`, `sign_ed25519.py`, `exercise-03-notes.md`, and the extended `week07.db` to your portfolio under `c50-week-07/exercise-03/`.
