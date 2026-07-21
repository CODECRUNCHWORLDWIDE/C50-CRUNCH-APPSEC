# Challenge 1 — Fix a Broken-Crypto Feature

**Estimated time:** 2 hours.

Crunch Vault needs a "forgot your vault passphrase" feature. Someone already built one — badly, stacking two of this week's failures on top of each other in a single feature. Your job: find both failures, fix both, and prove the fixed version resists the attacks the broken one didn't.

## The broken feature

Add this to `app.py` (or a new `reset.py` imported by it) and run it as-is first, so you can attack it before you fix it:

```python
import random
import sqlite3
import time

RESET_TOKENS = {}  # token -> (username, expires_at) -- in-memory, fine for this lab

def generate_reset_token() -> str:
    # BROKEN #1: random.randint is not a CSPRNG -- see Lecture 3, Section 3.
    return "".join(str(random.randint(0, 9)) for _ in range(6))

def store_reset_token(username: str) -> str:
    token = generate_reset_token()
    RESET_TOKENS[token] = (username, time.time() + 900)  # valid 15 minutes
    # BROKEN #2: the token is then "encrypted" for storage using the same
    # homemade XOR cipher this week's lecture broke -- see Lecture 3,
    # Section 4 -- reusing the SAME key for every token issued.
    from app import homemade_encrypt, VAULT_KEY
    encrypted_for_log = homemade_encrypt(token, VAULT_KEY)
    print(f"[audit] issued reset token (encrypted): {encrypted_for_log}")
    return token

def redeem_reset_token(token: str) -> str | None:
    entry = RESET_TOKENS.get(token)
    if entry is None:
        return None
    username, expires_at = entry
    if time.time() > expires_at:
        del RESET_TOKENS[token]
        return None
    del RESET_TOKENS[token]  # single use
    return username
```

## Part 1 — Attack it (so you know it's really broken)

Before fixing anything, demonstrate **both** flaws against your own running instance, offline:

1. **The RNG flaw.** A 6-digit token generated digit-by-digit with `random.randint(0, 9)` has only 1,000,000 possible values *in principle* — but because `random`'s internal state is small and reconstructible from enough observed output, an attacker who has seen a handful of tokens from the same process can often predict the *next* one directly, without brute-forcing the full keyspace. Write a short script that calls `generate_reset_token()` a few times, and in `challenge-01-notes.md` explain (referencing Lecture 3, Section 3) why "1,000,000 possibilities" already understates the real weakness here — the danger isn't just that the space is small, it's that the generator itself is predictable.
2. **The XOR flaw.** Call `store_reset_token()` for two different usernames, capture both `encrypted_for_log` outputs, and show — the same way Lecture 3 Section 4 did — that XOR-ing the two ciphertexts together recovers information about both tokens without ever knowing `VAULT_KEY`. This is worse here than in the original vault: reset tokens are short and highly structured (six digits), which makes the recovered XOR stream especially easy to split back into the two original values by hand.

## Part 2 — Fix it, end to end

Rewrite the feature so that:

- The token is generated with `secrets.token_urlsafe()` or `secrets.token_hex()` — not digits, not `random`.
- The token is never "encrypted" for logging at all — Lecture 1's rule from Section 4 applies here just as much as to a password: **don't log the value**, log that a reset was issued, to whom, and when.
- If you need to store a hashed reference to the token (e.g. to look up "was this token already used" without keeping the raw token around), hash it with SHA-256 — a reset token doesn't need password-hashing's deliberate slowness (nothing is brute-forcing a 128-bit random token offline the way it would a human-chosen password), but it does need a real cryptographic hash, not `homemade_encrypt`.
- The single-use and expiry logic from the original stays — those parts weren't broken.

## Part 3 — Prove the fix

Re-run both attacks from Part 1 against the fixed version and confirm they now fail:

- Generate 1,000 tokens with the fixed generator and confirm none repeat and none show any obvious digit-frequency skew (a simple `collections.Counter` over the token characters is enough).
- Confirm there's no XOR-recoverable ciphertext anywhere in the new logs, because there's no ciphertext of the token in the logs at all.

## Done when…

- [ ] `challenge-01-notes.md` documents both attacks against the broken version, with actual captured output (redacted appropriately), not just a description.
- [ ] The fixed `generate_reset_token()` uses `secrets`, not `random`.
- [ ] Nothing in the fixed feature logs a reset token's raw or "encrypted" value — only metadata (username, timestamp, expiry).
- [ ] Both re-run attacks from Part 3 demonstrably fail against the fixed version, and you've recorded why.
- [ ] `week07.db` has findings rows for both flaws in this feature, marked `purged`.

## Submission

Commit `reset.py` (or your merged `app.py`), `challenge-01-notes.md`, and your attack/verification scripts to your portfolio under `c50-week-07/challenge-01/`.
