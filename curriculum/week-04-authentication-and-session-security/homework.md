# Week 4 — Homework

Five problems, ~5 hours total, spread across the week. All work runs against `crunch-authlab` or synthetic data you generate yourself — nothing here touches a system you don't own. Commit each.

---

## Problem 1 — Compare DVWA's brute-force levels to your own defense (45 min)

DVWA's Brute Force module (`127.0.0.1:3001`, from your Week 1 lab) has four difficulty levels for the same login form — low (no defense), medium (a `sleep()` delay), high (a CSRF token plus the delay), impossible (parameterized queries, rate limiting, account lockout).

1. Using a small Python script (`requests`, a short wordlist), time how long 20 login attempts take against **low** and **medium**.
2. Read DVWA's own source for the **impossible** level (available in the container, or DVWA's public repository — see `resources.md`) and list, in your own words, the three defenses it stacks.
3. **Deliver** `dvwa-comparison.md`: your two timings, and one paragraph mapping DVWA's "impossible" defenses to the ones you built in Challenge 1 for `crunch-authlab`.

---

## Problem 2 — Build a password strength estimator (60 min)

Not every weak password looks obviously weak to a naive length/character-class check. `zxcvbn` (originally from Dropbox) scores passwords by realistic crackability, not composition rules.

1. `pip install zxcvbn`
2. Write `strength_check.py` that scores at least 10 passwords of your choosing — mix obviously weak (`password1`), composition-rule-satisfying-but-weak (`Passw0rd!`), and genuinely strong (a long random passphrase) — and prints the score (0–4) and `zxcvbn`'s human-readable feedback for each.
3. **Deliver** `strength_check.py` plus `strength-results.md`: the 10 outputs, and two sentences on a password that *passes* a classic "8+ chars, 1 uppercase, 1 digit, 1 symbol" rule but still scores low with `zxcvbn` — why does composition-rule strength diverge from real crackability?

---

## Problem 3 — Explain NIST 800-63B's break from old password rules (45 min)

In `nist-writeup.md`, answer in prose (no more than 400 words total):

1. NIST SP 800-63B (2017) dropped mandatory periodic password expiration and mandatory composition rules (must include a symbol, etc.) as *required* practices for most cases. Read the guideline (linked in `resources.md`) and explain, in your own words, why forced periodic rotation often makes password security *worse* in practice, not better.
2. What does 800-63B recommend **instead** of composition rules (hint: length, and checking against known-breached password lists)?
3. Connect this to Lecture 1: why does checking a submitted password against a breached-password list matter *even if* you're storing it correctly with argon2id?

---

## Problem 4 — Read WebAuthn, then write the comparison you couldn't build (60 min)

Lecture 2, Section 3 explained WebAuthn conceptually without a full implementation.

1. Read <https://webauthn.guide/> end to end (it's short).
2. In `webauthn-comparison.md`, write a table comparing TOTP and WebAuthn across at least five dimensions of your choosing (at minimum: phishing resistance, what's shared between client and server, what happens if the server's database is breached, setup friction for a non-technical user, and recovery-when-lost story).
3. Pick **one** open-source WebAuthn demo or library for Python or JavaScript (search is fine; note the one you found) and write two sentences on what registration would look like if you added it to `crunch-authlab` — you are not implementing it, just scoping the change.

---

## Problem 5 — Generate synthetic attack data and detect it in SQL (90 min)

Lecture 1, Section 7 gave you two detection queries against real data from your own testing. This problem asks you to detect attacks you **didn't** personally run — the realistic case, where you're handed a log and asked "did anything bad happen here?"

1. Write `generate_synthetic_events.py` that inserts **200 synthetic rows** into a fresh `login_events` table: ~150 "normal" scattered logins (varied usernames, varied IPs, varied timestamps across a day, mostly `success` with a few ordinary `bad_password`s), plus **one hidden brute-force burst** (one username, 12+ `bad_password` events from one IP within a 5-minute window) and **one hidden credential-stuffing burst** (one IP, 20+ distinct usernames, mostly `unknown_user`/`bad_password`, within a 5-minute window) — placed at timestamps you don't tell yourself in advance (have the script pick randomly, or ask a study partner to run it for you).
2. Without looking at the script's insert logic, write SQL queries against the resulting `login_events` table to find **both** hidden bursts — reuse and adapt Lecture 1, Section 7's two queries.
3. **Deliver** `generate_synthetic_events.py`, `detect.sql`, and `detection-results.md` showing the queries correctly isolated both synthetic attacks (paste the `source_ip`/`username` and window each query surfaced).

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 60 min |
| 3 | 45 min |
| 4 | 60 min |
| 5 | 90 min |
| **Total** | **~5 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
