# Week 7 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 8. A mix of multiple-choice and short "what's wrong with this code" — the answer key explains the *why*, not just the letter.

---

**Q1.** A team removes a `.env` file containing an AWS key in a commit, and confirms `git status` shows it gone. Is the key still exposed?

- A) No — once a file is deleted and committed, it's gone from the repo entirely.
- B) Yes — the file's contents are still reachable from earlier commits until history is rewritten and the old objects are pruned.
- C) Only if the file was never `.gitignore`d.
- D) Only if someone already cloned the repo before the deletion.

---

**Q2.** Which command lets you read a file's exact contents as they existed at a specific historical commit, even if the file no longer exists on the current branch?

- A) `git status`
- B) `git diff`
- C) `git show <commit-hash>:<path>`
- D) `git blame`

---

**Q3.** Why does rotation come *before* history-purging in this week's remediation sequence?

- A) Purging history is technically impossible before rotating.
- B) A secret that was ever pushed must be treated as compromised regardless of whether it's still findable — purging cleans up evidence, rotation is the actual fix.
- C) Git requires the working tree to be clean before rotation.
- D) It doesn't matter which comes first.

---

**Q4.** What's the main risk of logging a secret value, even at "debug" level?

- A) Debug logs are automatically encrypted, so there's no risk.
- B) Log files/aggregators are often readable by a much larger audience than the source repo, and the leak isn't visible in code review.
- C) Logging a secret is functionally identical to not logging it.
- D) There is no risk if the log file is deleted after 24 hours.

---

**Q5.** You need to verify a downloaded file matches its publisher's published checksum. Which primitive is correct?

- A) Symmetric encryption
- B) A cryptographic hash (e.g., SHA-256)
- C) A digital signature
- D) An HMAC

---

**Q6.** Why is SHA-256 the wrong choice for hashing passwords, even though it's a fine choice for file-integrity checks?

- A) SHA-256 is reversible.
- B) SHA-256 is fast, and password storage needs a deliberately slow, memory-hard function (bcrypt/scrypt/Argon2) to resist brute-force guessing.
- C) SHA-256 doesn't produce a fixed-size output.
- D) SHA-256 requires a key, which passwords don't have.

---

**Q7.** What does `Fernet` (or `AESGCM`) give you that plain AES-CBC with no additional authentication does not?

- A) A smaller ciphertext.
- B) Faster encryption speed.
- C) Tamper detection — decryption fails loudly if the ciphertext (or associated data) was altered.
- D) The ability to decrypt without the key.

---

**Q8.** Two 16-byte plaintext blocks are identical. Under AES-**ECB** mode, what happens to their ciphertext?

- A) The ciphertext blocks will also be identical — this is exactly ECB's structural weakness.
- B) The ciphertext blocks will always differ, because AES is a strong cipher.
- C) ECB mode refuses to encrypt repeated blocks.
- D) It depends on the key length.

---

**Q9.** A CBC-mode encryption function reuses the same static IV, `b"\x00" * 16`, for every message. What's the concrete consequence?

- A) None — the IV doesn't need to be secret, so a static one is fine.
- B) Two encryptions of the identical plaintext, with the same key and IV, produce identical ciphertext — leaking that the messages match, and weakening CBC's other guarantees.
- C) AES will throw an error if the IV is all zeros.
- D) Static IVs only matter for ECB mode, not CBC.

---

**Q10.** Why is `random.randint()` unsafe for generating an encryption key or a security token?

- A) It only produces even numbers.
- B) Its output is deterministic given its internal state/seed and is not designed to resist prediction — the opposite of what a security-relevant value needs.
- C) It's too slow for production use.
- D) It requires a network connection.

---

**Q11.** What are the two independent reasons a repeating-key XOR cipher fails as real encryption?

- A) It's too slow, and it requires asymmetric keys.
- B) It provides no authentication (tampering goes undetected), and reusing the key across messages lets an attacker cancel the key out via a two-ciphertext XOR.
- C) It can only encrypt text, not binary data.
- D) XOR is not a real mathematical operation.

---

**Q12.** In this week's `/webhook` route, `if given == expected:` compares a submitted signature to the correct one. Why is this specific comparison unsafe, independent of whether the signature values are ever logged?

- A) Python string equality is case-sensitive.
- B) `==` short-circuits at the first mismatched character, creating a timing side-channel an attacker can use to guess a valid signature byte by byte.
- C) `==` cannot compare hex strings.
- D) `expected` is computed with the wrong hash algorithm.

---

**Q13.** What is the correct fix for Q12's comparison?

- A) Compare the strings' lengths first, then use `==`.
- B) `hmac.compare_digest(given, expected)` — constant-time regardless of where the strings first differ.
- C) Convert both strings to uppercase before comparing.
- D) Use `<` instead of `==`.

---

**Q14.** What's the core difference between what encryption proves and what a digital signature proves?

- A) They prove the same thing; signatures are just slower.
- B) Encryption proves confidentiality (only the intended party can read it); a signature proves authenticity and integrity (who sent it, and that it wasn't altered) without necessarily hiding the content.
- C) Signatures require a shared secret; encryption never does.
- D) Encryption is always asymmetric; signatures are always symmetric.

---

**Q15.** A `secret_findings` table has a row for a payment API key found in `.env`'s git history. Which of the following, alone, is sufficient to mark that row's status `rotated`?

- A) The `.env` file no longer exists in the working tree.
- B) `git filter-repo` has purged the file from history.
- C) A new, different credential has been issued and the old one has been invalidated at the provider (e.g., Stripe), regardless of whether history has been purged.
- D) The finding has been open for less than 24 hours.

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — deleting a file in a new commit doesn't remove it from earlier commits; the blob is reachable via `git log -p`/`git show` until history is rewritten and old objects are pruned/garbage-collected.
2. **C** — `git show <commit>:<path>` prints a file's exact contents as of that commit, regardless of what the working tree or `HEAD` currently look like.
3. **B** — purging history is cleanup after the fact; rotation is what actually neutralizes the exposure, because the secret must be assumed compromised the moment it was ever pushed.
4. **B** — logs typically flow to aggregators with a much broader read audience than the source repo, and unlike a hardcoded secret, a logged one is invisible to code review.
5. **B** — a hash needs no key and answers "does this match," which is exactly an integrity check; encryption and signing both require key material this scenario doesn't need.
6. **B** — SHA-256's speed is a feature for integrity checks and a liability for passwords, where you want brute-forcing to be expensive; that's the entire reason bcrypt/scrypt/Argon2 exist as a separate category from general-purpose hashes.
7. **C** — authenticated modes add a MAC/tag so any tampering with the ciphertext causes decryption to fail loudly, instead of silently returning altered plaintext.
8. **A** — ECB encrypts each block independently with no chaining, so identical plaintext blocks always produce identical ciphertext blocks — the defining structural weakness of the mode.
9. **B** — CBC's IV must be unique per encryption; reusing it collapses one of CBC's core guarantees and, at minimum, reveals when two messages under the same key and IV are identical.
10. **B** — `random`'s Mersenne Twister PRNG is fast and high-quality for simulations but fully determined by its internal state, which can often be reconstructed from observed output — the opposite of what an unguessable key or token requires.
11. **B** — no authentication (undetected tampering) and key reuse across messages (which lets an attacker XOR two ciphertexts together and cancel the key out entirely) are two separate, independent failures.
12. **B** — `==` on strings returns as soon as it hits a mismatched character, so response timing correlates with how many leading characters were correct — a measurable side channel over enough network samples.
13. **B** — `hmac.compare_digest()` is specifically designed to take the same amount of time regardless of where (or whether) the two values differ.
14. **B** — encryption's job is confidentiality; a signature's job is proving origin and integrity, and a signed message is not thereby hidden from anyone who can read it.
15. **C** — neither removing the working-tree file (A) nor purging history (B) neutralizes a secret that may already have been seen or copied elsewhere; only issuing a new credential and invalidating the old one at the actual provider makes the row honestly `rotated`.

</details>

**Scoring:** 12+ → start Week 8. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; secrets and crypto mistakes compound silently, and this course assumes this week's habits are automatic from here on.
