# Week 4 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 5. A mix of multiple-choice and short scenario questions — the answer key explains the *why*, not just the letter.

---

**Q1.** A database breach exposes a `password_hash` column where every value is a plain SHA-256 digest, unsalted. What is the **most accurate** description of the risk?

- A) No risk — SHA-256 is a cryptographic hash, so the passwords are safe.
- B) High risk — SHA-256 is fast, so offline dictionary/brute-force cracking is cheap at scale, and identical passwords produce identical hashes.
- C) Medium risk, only if the attacker also has the salt.
- D) No risk, because SHA-256 is one-way and cannot be reversed.

---

**Q2.** What does a per-user salt specifically defend against?

- A) Slowing down the hash function itself
- B) Rainbow-table lookups and cross-user batch cracking (identical passwords no longer produce identical hashes)
- C) Credential stuffing
- D) Session fixation

---

**Q3.** Why is `argon2id` preferred over bcrypt as this course's default?

- A) It's older and more battle-tested
- B) It's memory-hard, which blunts the GPU/ASIC advantage that makes fast parallel cracking cheap
- C) It doesn't require a salt
- D) It's faster to compute, so login feels snappier

---

**Q4.** In the lazy-migration pattern (Lecture 1, Section 4.3), what happens to a user's stored hash if they never log in again after the app switches from SHA-256 to argon2id?

- A) It's automatically re-hashed by a background job
- B) It stays on the old SHA-256 hash until (if ever) they log in again and trigger the upgrade
- C) The account is automatically locked
- D) The migration fails and the app crashes

---

**Q5.** An attacker tries the password `Summer2024!` against 500 different usernames, spacing the attempts out over several hours to avoid triggering any single account's lockout. This is:

- A) Brute force
- B) Credential stuffing
- C) Password spraying
- D) Session fixation

---

**Q6.** Against a `login_events` table with `username`, `source_ip`, and `event_type` columns, which `GROUP BY` column is the right axis for detecting **credential stuffing** specifically?

- A) `event_type`
- B) `username`
- C) `source_ip`, counting `COUNT(DISTINCT username)`
- D) `occurred_at` alone, with no grouping

---

**Q7.** In TOTP (RFC 6238), the 6-digit code is derived from:

- A) `HMAC-SHA1(secret, current_time_counter)`, truncated
- B) `SHA-256(username + password)`
- C) A random number generated fresh by the server on every request
- D) The user's password, hashed with a time-based salt

---

**Q8.** Why is widening TOTP's `valid_window` from ±1 step to ±5 steps a meaningful security tradeoff, not just a usability nicety?

- A) It doesn't change security at all
- B) It increases the number of valid codes an online attacker could try within a guessing window against the verification endpoint
- C) It makes the shared secret weaker
- D) It disables rate limiting automatically

---

**Q9.** What specifically makes WebAuthn "phishing-resistant" in a way TOTP is not?

- A) WebAuthn codes are longer than TOTP codes
- B) The authenticator cryptographically binds the credential to the origin and refuses to sign a challenge for the wrong domain — a human doesn't have to catch the fake URL
- C) WebAuthn doesn't use cryptography, so there's nothing to phish
- D) WebAuthn requires a password in addition to the key

---

**Q10.** Why must recovery codes be stored hashed, and a used code marked consumed rather than deleted?

- A) Hashing them saves database space; deletion would corrupt the table
- B) Hashed storage prevents a database breach from handing out working MFA bypasses; marking (not deleting) preserves an audit trail that the code was used, once, and by whom
- C) Recovery codes don't need protection since they're single-use anyway
- D) Deletion is technically impossible in SQL

---

**Q11.** Why did NIST SP 800-63B classify SMS-delivered OTP as a *restricted* authenticator?

- A) SMS messages are always encrypted, so there's no risk
- B) It depends on the phone carrier correctly routing to the legitimate SIM — a SIM swap (a social-engineering attack on the carrier) can redirect delivery to an attacker with no app-side compromise at all
- C) SMS codes are too long for users to type accurately
- D) SMS is deprecated technology no phone supports anymore

---

**Q12.** What's wrong with generating a session ID as `f"{username}-{int(time.time())}"`?

- A) Nothing — it's unique per login
- B) It's guessable/constructible by an attacker who knows (or guesses) the username and an approximate login time, with far less than the entropy a real random token needs
- C) It's too long for a cookie
- D) Flask cannot store string cookies

---

**Q13.** Which cookie flag specifically prevents client-side JavaScript (`document.cookie`) from reading a session cookie, closing the most common XSS-based theft path?

- A) `Secure`
- B) `SameSite=Strict`
- C) `HttpOnly`
- D) `Max-Age`

---

**Q14.** In a session fixation attack, the attacker:

- A) Steals a victim's already-authenticated session ID directly
- B) Plants a known, unauthenticated session ID on the victim (e.g., via a crafted link) *before* login, then waits for the victim to authenticate under that same ID
- C) Guesses the victim's password via brute force
- D) Forges a JWT signature without the secret key

**Q14b.** What's the one-line fix?

- A) Add `HttpOnly` to the cookie
- B) Rotate to a brand-new session ID on every successful login (and again on MFA completion), discarding the pre-auth ID entirely
- C) Increase the argon2id cost parameters
- D) Rate-limit the login endpoint

---

**Q15.** A team is deciding between server-side sessions and JWTs for a traditional web app that needs to support "log this user out of all devices immediately" on a password change. Which is the better fit, and why?

- A) JWTs, because they're stateless and therefore always more secure
- B) Server-side sessions, because revocation is a direct database delete — a JWT can't be un-issued before it expires without reintroducing a server-side denylist, which defeats the point of using a JWT
- C) Either — they're functionally identical for this use case
- D) Neither — this requirement is impossible to implement

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — SHA-256 is fast by design, which is exactly wrong for password storage; offline cracking at scale is cheap, and without a salt, identical passwords collide to identical hashes.
2. **B** — a salt defeats rainbow tables and cross-user batch cracking. It does **not** slow the hash function down (that's argon2id's job) — see Lecture 1, Section 3.1.
3. **B** — argon2id is memory-hard, which specifically blunts the parallel-hardware advantage (GPUs/ASICs) that makes fast cracking cheap. Its tunable cost is the other half of the story.
4. **B** — lazy migration only upgrades a hash on next successful login; a user who never returns simply stays on the old scheme until (if ever) they do.
5. **C** — one common password, many usernames, deliberately spaced out to dodge per-account lockout thresholds: password spraying.
6. **C** — `GROUP BY source_ip` with `COUNT(DISTINCT username)` finds one IP hitting many accounts, the stuffing signature. `GROUP BY username` (B) is the brute-force axis instead.
7. **A** — `HMAC-SHA1(secret, current_time_counter)`, truncated per the RFC 6238 scheme described in Lecture 2, Section 2.1.
8. **B** — a wider window means more valid codes are simultaneously acceptable, directly increasing what an online guesser could try before a code rotates — which is also why the MFA endpoint itself needs rate limiting.
9. **B** — the authenticator checks the origin in hardware/OS code the phishing page can't spoof or intercept; no human judgment call about a URL is involved, unlike typing a TOTP code into whatever page asked for it.
10. **B** — hashed storage means a database breach doesn't hand out a working bypass list; marking `used_at` (rather than deleting) both enforces single-use and preserves the record that it happened.
11. **B** — SMS OTP delivery depends on carrier routing, which a SIM swap (a social-engineering attack on the carrier, not your app) can redirect — an attack surface entirely outside your code.
12. **B** — it's constructible, not random: an attacker who knows or guesses the username and a rough login timestamp can build valid-looking session IDs directly, with nowhere near the entropy `secrets.token_urlsafe(32)` provides.
13. **C** — `HttpOnly` specifically blocks JavaScript's `document.cookie` from reading the value, closing the primary XSS-based theft path. `Secure` (A) protects transport, not script access; `SameSite` (B) is the CSRF defense.
14. **B**, then **B** — fixation plants a pre-auth ID on the victim and waits for it to become authenticated; the fix is rotating to a fresh ID on login (and MFA completion) so the planted ID never becomes valid.
15. **B** — server-side sessions make "log out everywhere, right now" a direct database delete. JWTs can't be revoked before expiry without a server-side denylist, which reintroduces the exact state a JWT was meant to avoid — Lecture 3, Section 2's core tradeoff.

</details>

**Scoring:** 12+ → start Week 5. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; auth and session bugs compound into everything the rest of this course covers.
