# Week 9 — Quiz

Fifteen questions. Lectures closed. Aim for 12/15 before starting Week 10. A mix of multiple-choice and short "what category is this" questions — the answer key at the bottom explains the *why*, not just the letter.

---

**Q1.** What is the core structural reason APIs get their own OWASP Top 10, separate from the web Top 10?

- A) APIs are a completely different, unrelated field of study
- B) APIs have no browser/UI layer to hide fields from a user, and every endpoint is meant to be called programmatically, out of sequence, at whatever rate a script can manage
- C) The API Top 10 was published first and the web Top 10 copied it
- D) APIs never use databases, so different bugs apply

---

**Q2.** This code is vulnerable to which category?

```python
row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
```

(no check that `task_id` belongs to the caller's account)

- A) BFLA
- B) BOLA — Broken Object-Level Authorization
- C) Mass assignment
- D) Missing rate limiting

---

**Q3.** A route correctly checks that a valid Bearer token was presented, but never checks whether the token's `role` is `admin` before performing an admin-only delete. This is:

- A) BOLA
- B) BFLA — Broken Function-Level Authorization
- C) Excessive data exposure
- D) Not a vulnerability, since a valid token was presented

---

**Q4.** `columns = ", ".join(f"{k} = ?" for k in data.keys())` used to build an `UPDATE` from a client's raw JSON body is dangerous because:

- A) SQLite doesn't support dynamic column lists
- B) It lets the client set *any* column present in the table, including ones like `user_id` or a reward/balance field never meant to be client-writable
- C) It's slower than a static query
- D) JSON doesn't support dictionaries

---

**Q5.** Excessive data exposure and mass assignment are best described as:

- A) Unrelated bugs that happen to share a lecture
- B) Two directions (read and write) of the same missing control: an explicit allowlist of which object properties may cross the API boundary
- C) The same exact bug with two different names
- D) Only relevant to APIs that don't use HTTPS

---

**Q6.** Why does the fixed `GET /api/v1/tasks/<id>` route return `404` instead of `403` when a caller requests someone else's task?

- A) 404 is faster to compute than 403
- B) A 403 would confirm the object exists and belongs to someone else; a uniform 404 leaks nothing extra to a caller probing for valid IDs
- C) Flask doesn't support returning 403 from this kind of route
- D) There is no meaningful difference between the two

---

**Q7.** A JWT's payload (the claims section) is:

- A) Encrypted by default and unreadable without the signing key
- B) Base64-encoded, not encrypted — anyone holding the token can decode and read every claim
- C) Stored only on the server, never sent to the client
- D) Automatically rotated every request

---

**Q8.** The biggest practical cost of choosing JWTs for statelessness at scale is:

- A) JWTs are always larger than session cookies
- B) Revocation is delayed — a JWT issued for 24 hours remains valid for 24 hours even if the account is deleted 5 minutes later, unless a separate revocation mechanism is built
- C) JWTs cannot include a user ID
- D) JWTs require a database lookup on every request, defeating their purpose

---

**Q9.** What does a `marshmallow`/`pydantic` schema validate that a manual `{k: v for k, v in data.items() if k in ALLOWED}` allowlist does not?

- A) Nothing — they're functionally identical
- B) Types and shape constraints (e.g., a string where a string is expected, a length limit), on top of restricting which fields are present
- C) Whether the request used HTTPS
- D) The client's IP address

---

**Q10.** In the "fixed request" flowchart from Lecture 2, why does the rate-limit check run before the authentication check?

- A) It doesn't — authentication always runs first
- B) So that an attacker flooding the endpoint with invalid-credential attempts gets throttled before the server does the (comparatively expensive) work of checking credentials at all
- C) Rate limiting is unrelated to authentication and the order doesn't matter
- D) Flask requires rate limiting to be the first decorator applied

---

**Q11.** In the local dependency-confusion demo, the "public" impostor package (version `9.9.9`) gets installed instead of the real internal package (version `1.0.0`) because:

- A) The public index was listed first in `--find-links`
- B) `pip` prefers the highest version number across all configured sources by default, regardless of which source is "supposed" to be authoritative
- C) SQLite corrupted the internal package
- D) The internal package name was misspelled

---

**Q12.** The single structural fix that closes dependency confusion entirely, rather than just making it less likely, is:

- A) Renaming all your internal packages weekly
- B) Scoping/reserving your private package names (or restricting resolution to a single trusted index with no public fallback) so a name collision is structurally impossible
- C) Always installing the newest version of everything
- D) Disabling `pip` and only using manually downloaded files

---

**Q13.** `pip install --require-hashes -r requirements.lock.txt` protects against:

- A) Typos in package names only
- B) A package being served under the exact right name and version but with tampered file contents — the hash check fails if even one byte differs from what was pinned
- C) Slow network connections
- D) Nothing that plain version pinning (`flask==3.0.3`) doesn't already cover

---

**Q14.** An SBOM (software bill of materials) by itself:

- A) Automatically finds and fixes every vulnerability in your dependencies
- B) Lists what components you have — it makes scanning, provenance verification, and "are we affected by this new CVE" possible, but finding zero vulnerabilities is a separate step (the scan)
- C) Is only useful for licensing questions, never security
- D) Replaces the need for a `requirements.txt` entirely

---

**Q15.** Why is "always take the latest version of every dependency" not a safe default against a compromised-package attack, even though it's a reasonable default against already-known, already-scanned vulnerabilities?

- A) Latest versions are always slower
- B) A compromised maintainer account can publish a malicious version *after* the version you were previously pinned to — "latest" would pull that malicious version in automatically, before anyone has scanned or reported it
- C) `pip` cannot install the latest version of anything
- D) There is no real difference; latest is always safest

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — no HTML/UI layer to hide a field from a user, and every endpoint must assume programmatic, out-of-sequence, script-rate calls — the two structural differences Lecture 1 opens with.
2. **B** — an object (a task) is fetched by client-supplied ID with no check that the requesting caller actually owns it: the textbook BOLA.
3. **B** — the route checked *authentication* (a valid token exists) but never *authorization* (does this token's role permit this specific function) — exactly the BFLA pattern.
4. **B** — building the column list from the client's own JSON keys means the client controls which columns get written, including ones like `user_id` that were never meant to be client-settable.
5. **B** — mass assignment is the write-side failure to allowlist properties; excessive data exposure is the read-side failure of the same missing control.
6. **B** — a 403 confirms existence and ownership by someone else; a uniform 404 for "doesn't exist" and "not yours" gives an attacker probing IDs no extra information.
7. **B** — JWT payloads are base64-encoded (trivially decodable), not encrypted; only the signature (not the payload) is cryptographically protected against tampering.
8. **B** — a JWT remains valid until its `exp` claim expires regardless of what happens to the account afterward, unless a separate revocation mechanism (denylist, short expiry + refresh, token-version check) is built.
9. **B** — schemas add type checking and shape/length constraints on top of the field-presence filtering a manual allowlist already does.
10. **B** — throttling before authentication means an attacker flooding the endpoint gets rate-limited before the server spends any effort verifying (rejecting) their credentials, reducing wasted work and slowing brute-force attempts overall.
11. **B** — `pip`'s default behavior is to prefer the highest version number it can find across every configured source, regardless of which source is "supposed" to be authoritative for that name.
12. **B** — reserving/scoping the private name (or removing the public fallback entirely) makes the name collision itself impossible, rather than merely less likely.
13. **B** — hash verification checks the actual byte content of the downloaded file against a pinned hash, catching tampering that a plain `name==version` pin cannot, since a tampered file can still claim the exact right name and version.
14. **B** — an SBOM is an inventory, not a scanner; it's the prerequisite that makes scanning, provenance checks, and rapid CVE-impact assessment possible, but it does not itself detect a single vulnerability.
15. **B** — a compromised maintainer account can publish a malicious version after your current pin; "always latest" would install that malicious version automatically, with zero scanning or review, the moment it's published.

</details>

**Scoring:** 12+ → start Week 10. 9–11 → re-read the lecture sections behind your misses. <9 → re-read all three lectures from the top; Week 10 assumes this vocabulary — plus Weeks 3 and 6's authorization discipline — is automatic.
