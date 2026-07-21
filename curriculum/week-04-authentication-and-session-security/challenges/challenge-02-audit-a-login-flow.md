# Challenge 2 — Audit a Full Login Flow

**Time:** ~90 minutes. **Difficulty:** Medium–Hard. **No single right answer on presentation — but every real flaw must be found.**

## The scenario

You've spent three exercises fixing `crunch-authlab` one bug at a time, with the lecture telling you exactly what to look for. Real audits don't work that way — a teammate hands you a login flow and asks "is this safe?" with no hints. Below is the source for `crunch-second-app`, a small JWT-based login flow for a **different** fictional lab service. It was written quickly by someone who read half of Lecture 1 and none of Lectures 2–3. Find every authentication and session flaw in it.

**Run nothing against a real server for this challenge** — this is a **source-code review**, exactly like Week 1's attack-surface mapping and Week 2's threat modeling, done as a static read. If you want to stand the app up in your own isolated lab to confirm a finding hands-on, that's a welcome bonus, not a requirement.

## The source

```python
"""
crunch-second-app — a login flow for a different fictional lab service.
Review this. Do not assume it is safe anywhere it hasn't been proven safe.
"""
import hashlib
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "supersecret123"          # (1)

USERS = {
    "admin": {"password_hash": hashlib.md5(b"CrunchAdmin!2024").hexdigest(), "role": "admin"},   # (2)
    "bob":   {"password_hash": hashlib.md5(b"bobpassword").hexdigest(), "role": "user"},
}

LOGIN_ATTEMPTS = {}   # in-memory, never persisted, never checked                                  # (3)


@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]
    user = USERS.get(username)

    if user is None:
        return jsonify({"error": "no such user"}), 404                                            # (4)

    if hashlib.md5(password.encode()).hexdigest() != user["password_hash"]:                       # (5)
        return jsonify({"error": "wrong password"}), 401                                          # (4)

    # Client tells us their own role, and we just... believe it if present?                        # (6)
    role = request.json.get("role", user["role"])

    token = jwt.encode(
        {"username": username, "role": role},                                                     # (6)
        JWT_SECRET,
        algorithm="HS256",
    )   # no "exp" claim at all                                                                    # (7)
    return jsonify({"token": token})


@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    if payload["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    # ... delete the user ...
    return jsonify({"status": "deleted"})


@app.route("/logout", methods=["POST"])
def logout():
    # Nothing to invalidate — it's a JWT, so we just tell the client to forget it.                 # (8)
    return jsonify({"status": "logged out, please discard your token client-side"})
```

```javascript
// The front-end that talks to the API above:
async function doLogin(username, password) {
  const resp = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const { token } = await resp.json();
  localStorage.setItem("authToken", token);                                                      // (9)
}
```

The numbered comments above are **not** the answer key — they're just markers so you can reference specific lines in your write-up. Some numbered lines have more than one flaw; some flaws span multiple numbered lines; and there may be flaws that aren't marked at all. Don't assume the count of markers equals the count of findings.

## Your task

For **every** flaw you find:

1. **Name it** — which of this week's concepts does it violate (weak hashing, no salt, no lockout, session/token design, XSS-exposed token storage, missing expiry, trusting client input for authorization, CSRF, etc.)?
2. **State the concrete attack** — what would an attacker actually do with this, step by step, against a system they're authorized to test?
3. **State the fix** — the specific code change, referencing what you built in Exercises 1–3 where relevant.

Write it up in `challenge-02.md` as a numbered findings list, most severe first — the format a real security report uses.

## Constraints

- This is a **legal, defensive-minded, source-code review of fictional lab code** — you are reading, not attacking a live third-party system, and every finding must end in a defensive fix, per this course's standing ethics rule.
- Don't stop at the first flaw you find on the login route — this file has issues across password storage, MFA-adjacent design (there is no MFA at all here — is that itself worth flagging, and under what circumstance?), token/session lifecycle, authorization-via-token-claims, and client-side token storage.
- At least one flaw here is **not** something Exercises 1–3 covered directly (Lecture 3, Section 2's JWT-vs-session tradeoff is the closest lecture material gets) — that's intentional. State your reasoning even where the lecture didn't hand you the exact fix.

## Hints

<details>
<summary>If you're stuck after finding 4–5 flaws</summary>

Re-read Lecture 3, Section 2's JWT row on **revocation**, then look again at `/logout`. Also re-read the login route's `role` handling — where does that value actually come from, and who controls it?

</details>

<details>
<summary>On "should a login without MFA be flagged at all?"</summary>

MFA isn't universally mandatory for every account tier — but a fair finding is: *this app has no mechanism to add MFA at all*, which is a design gap, not a bug in running code. State it as a recommendation, not a "vulnerability" with a CVE-style severity, and explain the difference in your write-up.

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|---------------|
| Coverage | Finds only the MD5 password hash | Finds flaws across storage, tokens, authorization-via-claims, and client-side storage |
| Precision | "The JWT stuff seems bad" | Names the exact line, the exact attack, the exact fix |
| Severity judgment | Treats every finding as equally critical | Orders findings by real-world impact (e.g., client-controlled `role` claim outranks a missing rate limit) |
| Attacker/defender pairing | Lists attacks with no fixes, or fixes with no attack | Every finding closes with both, per this course's Week 1 habit |
| Restraint | Invents an attack against a real system to prove a point | Stays entirely within the fictional source review, as instructed |

## Submission

Commit `challenge-02.md` to your portfolio under `c50-week-04/challenge-02/`.
