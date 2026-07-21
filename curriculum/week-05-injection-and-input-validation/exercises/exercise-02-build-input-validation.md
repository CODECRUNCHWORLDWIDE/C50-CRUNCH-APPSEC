# Exercise 2 — Build Allowlist Input Validation

**Goal:** Exploit VULN #4 (OS command injection in `/diagnostics/ping`), then fix it with **allowlist** input validation — reject anything that isn't recognizably a hostname or IP address, rather than trying to blocklist dangerous shell characters.

**Estimated time:** 60 minutes.

## Before you start

Crunch Notes is running, and `findings.db` exists from Exercise 1.

## Task 1 — Exploit VULN #4

```bash
curl -s -X POST http://127.0.0.1:5000/diagnostics/ping -d "host=127.0.0.1; whoami"
curl -s -X POST http://127.0.0.1:5000/diagnostics/ping -d "host=127.0.0.1 && echo INJECTED"
```

Both should show your username (or `INJECTED`) in the response, appended after the normal `ping` output — proof a second command executed. Record the finding:

```python
import sqlite3
conn = sqlite3.connect("findings.db")
fid = conn.execute(
    "INSERT INTO findings (vuln_id, route, category, description) VALUES (?, ?, ?, ?)",
    ("VULN-4", "/diagnostics/ping", "cmdi", "Unsanitized host param passed to os.popen(); shell metacharacters execute a second command"),
).lastrowid
for payload, desc in [
    ("127.0.0.1; whoami", "Command separator"),
    ("127.0.0.1 && echo INJECTED", "Conditional chaining"),
    ("$(whoami)", "Command substitution"),
]:
    conn.execute(
        "INSERT INTO payload_library (category, payload, description) VALUES (?, ?, ?)",
        ("cmdi", payload, desc),
    )
conn.commit()
```

## Task 2 — Why a blocklist is the wrong tool here

Before writing the fix, write down (in a `why-not-blocklist.md`, 4–6 sentences) why blocking `;`, `&&`, `|`, and backticks one at a time is the wrong approach — name at least two shell metacharacters or techniques your list would still miss (hint: newlines, `||`, `$IFS` as a space substitute, or simply a payload using a metacharacter you didn't think to list). This isn't busywork — Lecture 1 Section 5 makes exactly this argument for SQL, and re-deriving it yourself for a different interpreter is how it sticks.

## Task 3 — Build the allowlist validator

A hostname/IP the ping diagnostic legitimately needs to accept is a narrow, well-defined shape. Use Python's `ipaddress` module for IPs and a strict regex for hostnames — reject everything else:

```python
import ipaddress
import re

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")

def is_valid_target(value: str) -> bool:
    """Allowlist: value must be a syntactically valid IPv4/IPv6 address OR a
    syntactically valid hostname -- nothing else is accepted, no matter what
    characters it contains."""
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(HOSTNAME_RE.match(value))
```

Notice what this function does NOT do: it never looks for `;`, `&`, `|`, or any other "bad" character by name. It defines what a **valid** value looks like and rejects everything that doesn't match — so a payload using a metacharacter nobody thought to blocklist is rejected anyway, simply because it isn't a valid hostname or IP.

## Task 4 — Wire it into the route and use a safe subprocess API

Validation alone isn't the whole fix — even a validated hostname shouldn't be handed to a shell string. Combine allowlist validation **with** `subprocess.run`'s list-argument form, which never invokes a shell at all:

```python
import subprocess

@app.route("/diagnostics/ping", methods=["GET", "POST"])
def ping():
    output = None
    error = None
    if request.method == "POST":
        host = request.form.get("host", "127.0.0.1")
        if not is_valid_target(host):
            error = "Invalid host: must be a valid IP address or hostname."
        else:
            # Safe: list-form subprocess.run never invokes a shell, so there
            # is no interpreter left for metacharacters to mean anything to.
            result = subprocess.run(
                ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
            )
            output = result.stdout
    return render_template_string(PING_FORM, output=output, error=error)
```

Update `PING_FORM` to show `{% if error %}<p style="color:red">{{ error }}</p>{% endif %}`. Restart the app.

**Why both layers matter, not just one:** the allowlist stops a request from *reaching* the shell call with a malicious value; `subprocess.run([...])` (list form, no `shell=True`) means that even if a validation bug ever let something slip through, there's still no shell parsing the string for metacharacters to exploit. Defense-in-depth, same idea as CSP backing up output encoding in Lecture 3.

## Task 5 — Verify

```python
import sqlite3, requests

conn = sqlite3.connect("findings.db")
finding_id = conn.execute("SELECT id FROM findings WHERE vuln_id = 'VULN-4'").fetchone()[0]
payloads = conn.execute("SELECT id, payload FROM payload_library WHERE category = 'cmdi'").fetchall()

for payload_id, payload in payloads:
    resp = requests.post("http://127.0.0.1:5000/diagnostics/ping", data={"host": payload})
    blocked = "Invalid host" in resp.text
    conn.execute(
        "INSERT INTO verifications (finding_id, payload_id, result) VALUES (?, ?, ?)",
        (finding_id, payload_id, "blocked" if blocked else "allowed"),
    )
conn.commit()
```

Also confirm a **legitimate** value still works: `curl -s -X POST http://127.0.0.1:5000/diagnostics/ping -d "host=127.0.0.1"` should return real ping output, not an error — a validator that rejects everything (including valid input) isn't a fix, it's a different kind of broken.

## Expected result

- All three `cmdi` payloads in `verifications` show `result = 'blocked'`.
- `host=127.0.0.1` and `host=localhost` still succeed.
- `host=127.0.0.1; whoami` returns the "Invalid host" message, not ping output plus a username.

## Done when…

- [ ] `is_valid_target()` exists, uses `ipaddress` + a hostname regex, and contains **no** blocklist of "bad characters."
- [ ] The route uses `subprocess.run([...])` (list form, no `shell=True`), not `os.popen()`/`os.system()`.
- [ ] `why-not-blocklist.md` names at least two concrete bypasses a naive blocklist would miss.
- [ ] Verification results are in `verifications` for all three `cmdi` payloads, all `blocked`, and a legitimate host still works.

## Stretch

- Add a payload using a newline (`127.0.0.1\nwhoami`) and confirm your regex rejects it too (most naive regexes anchored with `^`/`$` without the `re.MULTILINE` flag already handle this correctly by accident — explain in one sentence why, in `why-not-blocklist.md`).
- Extend the allowlist to also reject private/loopback-adjacent ranges you don't want probed (e.g., only allow `127.0.0.1`-scoped RFC 1918 addresses) — a scope restriction on top of a syntax restriction, the same "narrower is safer" instinct as least privilege.

## Submission

Commit the updated `app.py`, `is_valid_target()` (as its own `validation.py` module is fine), `why-not-blocklist.md`, and updated `findings.db` to `c50-week-05/exercise-02/`.
