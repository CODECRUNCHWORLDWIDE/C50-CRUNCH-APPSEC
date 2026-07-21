# Week 4 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Install first

- **`argon2-cffi`** — Python bindings for argon2id, this week's default password hasher: `pip install argon2-cffi` · docs: <https://argon2-cffi.readthedocs.io/>
- **`pyotp`** — TOTP generation and verification: `pip install pyotp` · docs: <https://pyauth.github.io/pyotp/>
- **`zxcvbn`** (homework Problem 2) — realistic password strength scoring: `pip install zxcvbn`
- **An authenticator app** for testing TOTP enrollment yourself — any of these work and are free: Google Authenticator, Microsoft Authenticator, Authy, or 1Password's built-in TOTP support. Prefer a CLI tool for quick testing without a phone? `pip install oathtool` (or your OS package manager's `oathtool`) generates codes from a base32 secret on the command line.
- **Your Week 1 `appsec-lab`** must already be up with DVWA reachable at `127.0.0.1:3001` — see [Week 1's lab lecture](../week-01-appsec-foundations-and-threat-landscape/lecture-notes/03-building-a-legal-isolated-lab.md) if you need to rebuild it.

## Required reading (this week's core)

- **OWASP — Password Storage Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
  *Why: the canonical, current guidance behind everything in Lecture 1 — algorithm choices, parameters, and migration.*
- **OWASP — Credential Stuffing Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html>
  *Why: the reference for Challenge 1's defenses, beyond what this week's lecture had room for.*
- **RFC 6238 — TOTP:** <https://datatracker.ietf.org/doc/html/rfc6238>
  *Why: the actual specification behind Lecture 2, Section 2 — short, and worth reading once end to end.*
- **webauthn.guide:** <https://webauthn.guide/>
  *Why: the clearest plain-language walkthrough of WebAuthn/FIDO2; required for Homework Problem 4.*
- **OWASP — Session Management Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
  *Why: the reference behind every claim in Lecture 3 — cookie flags, fixation, timeout.*

## Reference (keep in tabs)

- **OWASP — Multifactor Authentication Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html>
- **OWASP — Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet:** <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **MDN — Using HTTP cookies:** <https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies>
  *Why: the browser-side contract for `Set-Cookie`, `HttpOnly`, `Secure`, `SameSite` — bookmark it.*
- **NIST SP 800-63B — Digital Identity Guidelines, Authentication and Lifecycle Management:** <https://pages.nist.gov/800-63-3/sp800-63b.html>
  *Why: the source document for Homework Problem 3 and the "restricted authenticator" language around SMS OTP.*
- **Python `secrets` module docs:** <https://docs.python.org/3/library/secrets.html>
  *Why: the only correct source of randomness for session IDs and tokens this week — never `random`.*
- **DVWA — official repository (source for the brute-force module's four difficulty levels):** <https://github.com/digininja/DVWA>
  *Why: Homework Problem 1 asks you to read the "impossible" level's actual PHP source.*

## Practice beyond the lab

- **PortSwigger Web Security Academy — Authentication:** <https://portswigger.net/web-security/authentication>
  *Why: free, browser-based labs specifically on broken authentication, in PortSwigger's own isolated lab instances — a natural next step after this week's exercises.*
- **PortSwigger Web Security Academy — Session hijacking / CSRF:** <https://portswigger.net/web-security/csrf> and <https://portswigger.net/web-security/session-hijacking>
  *Why: more reps on Lecture 3's concepts with different vulnerable apps.*
- **OWASP Juice Shop** (already running from Week 1, `127.0.0.1:3000`) — try logging in as its admin account using only what you learned about credential stuffing and default credentials this week; its official companion guide has hints if you get stuck.

## Glossary

| Term | Definition |
|------|------------|
| **Salt** | Random, per-user data mixed into a password before hashing; defeats rainbow tables and cross-user batch cracking. |
| **Slow / memory-hard hash** | A password hashing function (argon2id, bcrypt, scrypt) deliberately expensive to compute, unlike a general-purpose hash. |
| **Offline cracking** | Guessing passwords against a stolen hash on attacker-controlled hardware, with no rate limit from the victim's server. |
| **Credential stuffing** | Replaying username/password pairs leaked from a *different* breach against your login, betting on password reuse. |
| **Password spraying** | Trying one common password across many accounts, spaced out to dodge per-account lockout. |
| **Brute force** | Exhaustively guessing passwords for one specific account. |
| **MFA / 2FA** | Requiring a second, independent proof of identity beyond a password — something you have or are, not just know. |
| **TOTP** | Time-based One-Time Password (RFC 6238) — a 6-digit code derived from a shared secret and the current time. |
| **WebAuthn / FIDO2** | A public-key-based authentication standard where the credential is cryptographically bound to the origin — phishing-resistant by construction. |
| **Recovery code** | A one-time backup credential issued at MFA enrollment for when the primary second factor is lost; must be hashed like a password. |
| **Session fixation** | An attacker plants a known session ID on a victim before login, hoping it becomes authenticated without being rotated. |
| **Session hijacking** | An attacker steals a victim's already-valid session ID directly (XSS, network sniff, log leak). |
| **CSRF** | Cross-Site Request Forgery — a malicious site triggers a state-changing request that the victim's browser authenticates automatically via cookies. |
| **`HttpOnly`** | A cookie flag preventing JavaScript from reading the cookie's value — the primary defense against XSS-based session theft. |
| **`SameSite`** | A cookie flag controlling whether the cookie is sent on cross-site requests — the primary defense against CSRF. |
| **Idle timeout** | Session expiry after a period of inactivity. |
| **Absolute timeout** | Session expiry after a fixed maximum lifetime, regardless of activity. |
| **JWT** | JSON Web Token — a signed, self-contained token; cannot be revoked before expiry without a server-side denylist. |

---

*Broken link? Open an issue or PR.*
