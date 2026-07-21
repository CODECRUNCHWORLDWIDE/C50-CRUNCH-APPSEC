# Lecture 1 — The API Top 10 Risks

> **Duration:** ~2 hours. **Outcome:** You can explain why APIs get their own OWASP Top 10, name and define BOLA, BFLA, mass assignment, excessive data exposure, and missing rate limits, and you've demonstrated and fixed all five against `crunch-tasks-api`.

## 1. Why APIs get their own Top 10

Week 3 gave you the OWASP (web) Top 10 — ten categories built from testing data on browser-facing applications. The **OWASP API Security Top 10** is a separate list, maintained by the same organization, because APIs fail in ways the web list doesn't fully capture. Three structural differences explain why:

1. **No browser, no UI, often no human watching the response.** A web app's HTML can hide a button from a low-privilege user; an API has no button to hide — every field an endpoint returns is available to whatever code is calling it, whether that's your own mobile app, a partner's integration, or an attacker's script. "The UI doesn't show that" was always a weak defense on the web (Week 3, Week 6); on an API it isn't a defense at all, because there's no UI in the loop.
2. **Every endpoint is, by design, meant to be called programmatically.** A web app can lean on a human clicking through a predictable sequence of pages. An API has to assume every endpoint will be hit directly, out of sequence, with hand-crafted parameters, at whatever rate a script can manage — which is exactly why rate limiting and object-level checks matter so much more here than they do on a page a human has to click through by hand.
3. **The data model is closer to the surface.** A web response is HTML, shaped by a template that (usually) only renders the fields the page needs. An API response is very often *the database row itself*, serialized directly to JSON — which means "I forgot to filter which columns come back" is a one-line bug away from leaking a password hash, not a template-authoring mistake that's harder to make by accident.

## 2. The OWASP API Security Top 10 (2023) — the five this week covers

The full API Top 10 has ten categories; this week gives full-lecture depth to the five with the highest real-world incidence in API-specific breach and bug-bounty data, and Lecture 2 covers the design disciplines (authentication, validation, output shaping, rate limiting, versioning) that prevent all ten at once, not just these five.

| Rank | Category | One-line pattern |
|---|---|---|
| **API1** | Broken Object-Level Authorization (BOLA) | An endpoint fetches an object by client-supplied ID with no check that the caller owns it |
| **API3** | Broken Object-Property-Level Authorization (mass assignment / excessive data exposure) | The API lets a client read or write object *properties* it was never authorized to touch |
| **API4** | Unrestricted Resource Consumption | No rate limit, size limit, or cost control on an endpoint a script can call as fast as the network allows |
| **API5** | Broken Function-Level Authorization (BFLA) | An endpoint performs a privileged *action* with no check that the caller's role permits it |

API3 in the official 2023 list actually bundles what earlier editions split into two: **excessive data exposure** (the API *returns* fields it shouldn't) and **mass assignment** (the API *accepts and writes* fields it shouldn't). They're two directions of the same root problem — no explicit allowlist of which object properties cross the API boundary — so this lecture treats them as a pair, the way the current OWASP edition does.

Notice the family resemblance to Week 3's web Top 10: BOLA is IDOR wearing an API's clothes; BFLA is the "missing function-level access control" pattern from Week 3's `/admin/users`, applied to an API route instead of a web route. **The concept doesn't change. The transport does.** You're about to see the exact same two questions from Week 6 — "who is this?" and "is *this specific* identity allowed *this specific* action on *this specific* object?" — asked again, this time of a Bearer token instead of a session cookie.

## 3. API1 — Broken Object-Level Authorization (BOLA)

**BOLA** happens when an endpoint accepts a client-supplied object identifier — a URL path parameter, a query string value, a body field — and uses it to fetch or modify an object with no check that the *authenticated caller* is authorized for *that specific* object. It is the API Top 10's #1 category, for the same reason IDOR topped Week 3's web list: it's simple to introduce (one missing predicate) and devastating when it ships, because the fix is almost always "the developer forgot one `WHERE` clause," not a deep architectural flaw.

`crunch-tasks-api`'s `/api/v1/tasks/<task_id>` is a textbook case:

```python
@app.route("/api/v1/tasks/<task_id>")
def get_task(task_id):
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    # VULNERABLE (BOLA) — no check that this task belongs to the caller
    row = get_db().execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
```

The route checks *authentication* — is this a real token — and stops. It never asks the second question: is the task at this ID one this caller is allowed to see. Any valid Bearer token can walk every integer ID in the table.

**Demonstrate it:**

```bash
# alice's own task (id 1) — expected, fine
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/1

# bob's task (id 3), read using ALICE's token — she was never granted this
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/tasks/3
```

The second request returns Bob's "Rotate deploy key" task body to Alice's token. No cookie, no session, no browser involved anywhere — just a header and an integer she incremented.

```mermaid
sequenceDiagram
  participant Client as Alice's token
  participant API as GET tasks endpoint
  participant DB as Tasks table

  Client->>API: Request task 3
  API->>API: Check token is valid
  Note over API: No ownership check performed
  API->>DB: SELECT task WHERE id equals 3
  DB-->>API: Bob's task row
  API-->>Client: Returns Bob's task data
```

*BOLA: the endpoint verifies the token is real but never asks whether task 3 belongs to Alice.*

**Remediate it** — add the ownership predicate directly into the query, exactly like Week 3 and Week 6's fix:

```python
@app.route("/api/v1/tasks/<task_id>")
def get_task(task_id):
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    row = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, user["id"]),
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))
```

**Re-test:** the same request with Alice's token against task 3 must now return `{"error":"not found"}` with a 404 — not a 403, and for the same reason as Week 3: a 403 confirms task 3 *exists* and belongs to somebody; a uniform 404 leaks nothing extra to a caller probing for valid IDs.

## 4. API5 — Broken Function-Level Authorization (BFLA)

Where BOLA is "wrong object," **BFLA** is "wrong function entirely" — the endpoint performs an action that should be restricted to a role, and nothing checks the role.

```python
@app.route("/api/v1/admin/tasks/<task_id>", methods=["DELETE"])
def admin_delete_task(task_id):
    user = current_user()
    # VULNERABLE (BFLA) — checks that SOME valid token was presented,
    # never that the caller's role is 'admin'
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    get_db().execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    get_db().commit()
    return jsonify(message=f"task {task_id} deleted")
```

**Demonstrate it:**

```bash
# alice is role='user', not 'admin' — yet this succeeds
curl -s -X DELETE -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/admin/tasks/2
```

Alice just deleted a task through an endpoint whose URL alone (`/admin/`) signals it should never have been reachable by her. In real APIs, this exact shape — a privileged route reachable by *any* valid caller because only "is there a token" was checked — is how a mobile app's regular-user token ends up able to hit the same backend routes the internal admin dashboard uses, simply because both talk to the same API.

**Remediate it** with an explicit, deny-by-default role check — the same `require_role` shape from Week 6, applied here to a token lookup instead of a session:

```python
def require_role(user, role):
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    if user["role"] != role:
        return jsonify(error="forbidden"), 403
    return None


@app.route("/api/v1/admin/tasks/<task_id>", methods=["DELETE"])
def admin_delete_task(task_id):
    user = current_user()
    denial = require_role(user, "admin")
    if denial:
        return denial
    get_db().execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    get_db().commit()
    return jsonify(message=f"task {task_id} deleted")
```

**Re-test both directions:** Alice's token must now get `{"error":"forbidden"}` with a 403; Bob's token (role `admin`) must still succeed. A fix that blocks Bob too isn't a fix — it's a different bug.

## 5. API3 — Mass Assignment

**Mass assignment** happens when an endpoint takes a client-supplied JSON body and writes *every key in it* to the underlying object, with no allowlist restricting which fields the client is actually permitted to set. It's a write-side property-level authorization failure: the object-level check might be perfect (the caller really does own this row), but the API never asked "of the fields you sent, which ones are actually yours to change?"

`crunch-tasks-api` has this flaw twice — once on account creation, once on update:

```python
@app.route("/api/v1/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    ...
    # VULNERABLE (mass assignment) — every key the client sends is written
    # straight into the INSERT, including 'role' and 'credits'
    db.execute(
        "INSERT INTO users (username, email, password_hash, api_token, role, credits) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (data.get("username"), data.get("email"), sha256(data.get("password", "")),
         token, data.get("role", "user"), data.get("credits", 0)),
    )
```

**Demonstrate it** — a brand-new signup grants itself `admin` on the way in:

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"mallory","email":"mallory@crunch.io","password":"pw","role":"admin","credits":99999}'
```

Nothing in the route stops `role` or `credits` from being present in the body — the account is created exactly as requested, admin privileges and all, from a public registration endpoint.

The second instance is worse, because it's not even a fixed field list — it's *arbitrary*:

```python
@app.route("/api/v1/tasks/<task_id>", methods=["PATCH"])
def update_task(task_id):
    ...
    data = request.get_json(force=True, silent=True) or {}
    # VULNERABLE (mass assignment) — every key in the request body is
    # written into the UPDATE, unfiltered
    columns = ", ".join(f"{k} = ?" for k in data.keys())
    db.execute(f"UPDATE tasks SET {columns} WHERE id = ?", (*data.values(), task_id))
```

**Demonstrate it:**

```bash
# alice reassigns bob's task to herself just by including user_id in the body
curl -s -X PATCH -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "reward_cents": 500000}' \
  http://127.0.0.1:5000/api/v1/tasks/3
```

This single request both steals a task's ownership *and* pays out half a million cents for it — and it works whether or not the BOLA fix above is applied, because this bug isn't about which task you can reach, it's about which *columns* of the task you can rewrite once you're in.

**Remediate both with an explicit allowlist** — never build a query from `dict.keys()` directly:

```python
ALLOWED_REGISTER_FIELDS = {"username", "email", "password"}
ALLOWED_TASK_UPDATE_FIELDS = {"title", "body", "is_complete"}


@app.route("/api/v1/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    clean = {k: v for k, v in data.items() if k in ALLOWED_REGISTER_FIELDS}
    ...
    db.execute(
        "INSERT INTO users (username, email, password_hash, api_token, role, credits) "
        "VALUES (?, ?, ?, ?, 'user', 0)",
        (clean.get("username"), clean.get("email"), sha256(clean.get("password", "")), token),
    )


@app.route("/api/v1/tasks/<task_id>", methods=["PATCH"])
def update_task(task_id):
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    data = request.get_json(force=True, silent=True) or {}
    clean = {k: v for k, v in data.items() if k in ALLOWED_TASK_UPDATE_FIELDS}
    if not clean:
        return jsonify(error="no updatable fields provided"), 400
    db = get_db()
    columns = ", ".join(f"{k} = ?" for k in clean.keys())
    db.execute(
        f"UPDATE tasks SET {columns} WHERE id = ? AND user_id = ?",
        (*clean.values(), task_id, user["id"]),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, user["id"])
    ).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)
```

Notice `role` and `credits` no longer appear anywhere in the register route's write path — they're hardcoded server-side defaults, not client input, full stop. The task-update fix does two jobs at once: the allowlist stops mass assignment, and the reinstated `AND user_id = ?` (Section 3's BOLA fix) stops the ownership theft. Both were needed; neither alone would have closed both holes.

**Re-test:** re-run both demonstration commands. Registration with `"role":"admin"` in the body must now create a plain `user`-role account; the `PATCH` with `user_id`/`reward_cents` must now return a `400` (both keys are outside the allowlist, so `clean` is empty) — and a legitimate `PATCH` with `{"title": "..."}` on your *own* task must still succeed.

## 6. API3 (the other direction) — Excessive Data Exposure

Mass assignment is the *write* direction of "no property-level allowlist." **Excessive data exposure** is the *read* direction: an endpoint returns the whole underlying object instead of exactly the fields the caller needs.

```python
@app.route("/api/v1/users/me")
def whoami():
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    # VULNERABLE (excessive data exposure) — returns the ENTIRE row
    return jsonify(dict(user))
```

**Demonstrate it:**

```bash
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/users/me
```

The response includes `password_hash` and `api_token` — fields the client already has (the token) or should never see in a response body at all (the hash). This is the same shape of mistake as `SELECT *` in Week 1 of Crunch SQL: it's convenient, and it silently returns more than anyone asked for, including fields added *after* this route was written that nobody thought to re-audit.

**Remediate it** — build the response from an explicit list of fields the client is meant to see, never `dict(row)` directly:

```python
@app.route("/api/v1/users/me")
def whoami():
    user = current_user()
    if user is None:
        return jsonify(error="invalid or missing token"), 401
    return jsonify(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        credits=user["credits"],
    )
```

**Re-test:** the same request must now return exactly those five fields — confirm `password_hash` and `api_token` are gone from the response with a simple `grep`:

```bash
curl -s -H "Authorization: Bearer tok_alice_LABONLY_0001" \
  http://127.0.0.1:5000/api/v1/users/me | grep -c password_hash   # expect: 0
```

## 7. API4 — Unrestricted Resource Consumption (missing rate limits)

The last category this lecture demonstrates is an *absence*, the same way A09 Logging Failures was in Week 3: `/api/v1/login` has no attempt counter, no delay, and no lockout.

```python
@app.route("/api/v1/login", methods=["POST"])
def login():
    # VULNERABLE (missing rate limiting) — no attempt counter, no lockout,
    # no delay, no CAPTCHA
    ...
```

**Demonstrate it** — a trivial loop, run entirely against your own `127.0.0.1` lab target, showing the endpoint accepts unlimited attempts with no friction:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://127.0.0.1:5000/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"guess'"$i"'"}'
done
echo
```

Every one of those twenty requests returns `401` instantly, with no growing delay and no eventual lockout — nothing distinguishes attempt 1 from attempt 10,000 except how long you're willing to wait for the script to finish. Lecture 2 covers the actual fix (a rate limiter) as part of the general API-design discipline, since "add a rate limiter" is a pattern that applies to every endpoint in the app, not a one-line patch specific to `/login`.

## 8. The pattern behind all five

Every category this lecture covered traces back to one missing question, asked at a different layer each time:

| Category | The question the endpoint forgot to ask |
|---|---|
| BOLA | "Does *this specific* object belong to the caller?" |
| BFLA | "Is the caller's *role* allowed to call this *function* at all?" |
| Mass assignment | "Which *fields* in this request body is the caller actually allowed to set?" |
| Excessive data exposure | "Which *fields* of this object does the caller actually need to see?" |
| Missing rate limits | "How many times has this caller tried this in the last minute?" |

Same discipline every time: **deny by default, check the specific thing, at the point of use** — the exact principle from Week 6, now applied to five different points of use on an API instead of one.

## 9. Check yourself

- In one sentence, what's the structural reason APIs get their own OWASP Top 10 instead of reusing the web list?
- Why is BOLA described as "IDOR wearing an API's clothes"? What actually changed, and what didn't?
- Mass assignment and excessive data exposure are two directions of the same missing control — name the control, and name which direction (read/write) each category represents.
- Why does the fixed `PATCH /api/v1/tasks/<id>` route need *both* the allowlist and the `AND user_id = ?` predicate? What would happen with only one of the two?
- Why is a uniform `401`/`404` response, with no growing delay, evidence of a missing rate limit rather than proof the endpoint is otherwise secure?

Lecture 2 turns these five demonstrated fixes into general design principles you can apply to an API you haven't seen before: authentication choices, input validation at the edge, output shaping, real rate limiting, and versioning without leaking what's running underneath.

## Further reading

- **OWASP API Security Top 10 (2023) — full list:** <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- **OWASP API Security — API1:2023 Broken Object Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- **OWASP API Security — API3:2023 Broken Object Property Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>
- **OWASP API Security — API5:2023 Broken Function Level Authorization:** <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
