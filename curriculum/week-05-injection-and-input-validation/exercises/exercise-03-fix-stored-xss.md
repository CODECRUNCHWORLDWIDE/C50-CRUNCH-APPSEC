# Exercise 3 — Fix a Stored XSS

**Goal:** Exploit VULN #3 (stored XSS in `/notes`), fix it with correct output encoding, and verify. Stretch goal applies the exact same rule to VULN #2's reflected half and VULN #7's DOM-based XSS.

**Estimated time:** 90 minutes (60 core + 30 stretch).

## Before you start

Crunch Notes is running, `findings.db` exists from Exercises 1–2.

## Task 1 — Exploit VULN #3

Post a malicious note:

```bash
curl -s -X POST http://127.0.0.1:5000/notes/new \
  -d "author=attacker&title=hi&body=<img src=x onerror=\"document.title='XSS-FIRED'\">"
```

Load `http://127.0.0.1:5000/notes` in an actual browser (not just `curl` — you need a real HTML/JS parser to see the payload execute). Confirm the browser tab's title changes to `XSS-FIRED`. This is the "damage" a real payload would do — a real attacker's script would read `document.cookie` or make an authenticated request on the victim's behalf, not just rename the tab.

Record the finding:

```python
import sqlite3
conn = sqlite3.connect("findings.db")
fid = conn.execute(
    "INSERT INTO findings (vuln_id, route, category, description) VALUES (?, ?, ?, ?)",
    ("VULN-3", "/notes", "xss", "Stored XSS: note body rendered with |safe, disabling Jinja2 autoescape"),
).lastrowid
pid = conn.execute(
    "INSERT INTO payload_library (category, payload, description) VALUES (?, ?, ?)",
    ("xss", "<img src=x onerror=\"document.title='XSS-FIRED'\">", "onerror handler fires without a real script tag"),
).lastrowid
conn.commit()
print(fid, pid)
```

## Task 2 — Fix it: remove the escape hatch

Open `app.py`. The bug is exactly one filter, in exactly one place:

```html
<!-- VULNERABLE -->
<div><b>{{ n['title'] }}</b> by {{ n['author'] }}<br>{{ n['body']|safe }}</div>

<!-- FIXED -->
<div><b>{{ n['title'] }}</b> by {{ n['author'] }}<br>{{ n['body'] }}</div>
```

Remove `|safe`. That's the entire code change — Jinja2's default autoescaping does the rest. Restart the app.

## Task 3 — Verify

Re-run the exact payload from Task 1 through `/notes/new`, then load `/notes` again:

```python
import requests

requests.post("http://127.0.0.1:5000/notes/new", data={
    "author": "attacker2", "title": "hi2",
    "body": "<img src=x onerror=\"document.title='XSS-FIRED-2'\">",
})
resp = requests.get("http://127.0.0.1:5000/notes")
blocked = "&lt;img" in resp.text and "<img src=x" not in resp.text
print("blocked" if blocked else "ALLOWED -- fix did not work")
```

Load `/notes` in a real browser again: the tab title should **not** change this time, and you should see the literal text `<img src=x onerror=...>` printed on the page as visible text, not executed. Record the verification:

```python
import sqlite3
conn = sqlite3.connect("findings.db")
conn.execute(
    "INSERT INTO verifications (finding_id, payload_id, result) VALUES (?, ?, ?)",
    (fid, pid, "blocked" if blocked else "allowed"),
)
conn.commit()
```

## Expected result

- Before the fix: browser tab title changes to `XSS-FIRED` when `/notes` loads.
- After the fix: the payload appears as visible, inert text on the page; tab title never changes; response HTML contains `&lt;img` (entity-encoded), not a live `<img>` tag.
- `verifications` shows `result = 'blocked'` for VULN-3's payload.

## Done when…

- [ ] `|safe` is removed from the `/notes` template, and stored payloads render as inert text.
- [ ] You verified the fix in an actual browser, not just by grepping the response body — XSS is a *browser-parsing* bug; confirm it against a real parser at least once.
- [ ] `findings.db` has VULN-3's finding, payload, and a `blocked` verification row.

## Stretch — apply the same rule to VULN #2 and VULN #7

**VULN #2 (reflected, in `/search`):** Remove `|safe` from `{{ q|safe }}` too. Verify with `curl -s "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"` — the response should contain `&lt;script&gt;`, not a live `<script>` tag. Note: the SQLi half of `/search` should already be fixed from Exercise 1 — if it isn't, do that first; this stretch task only addresses the XSS half.

**VULN #7 (DOM-based, in `/welcome`):** This one is **not** a server-side fix — the bug is entirely in the inline `<script>` block. Change:

```javascript
// VULNERABLE
document.getElementById("greeting").innerHTML = "Hi, " + name + "!";

// FIXED
document.getElementById("greeting").textContent = "Hi, " + name + "!";
```

Verify by visiting `http://127.0.0.1:5000/welcome?name=<img src=x onerror=alert(1)>` in a browser — you should see the literal text `Hi, <img src=x onerror=alert(1)>!` printed on the page, with no alert box, because `textContent` never asks the browser to parse it as HTML at all. Record both as findings/verifications the same way as Task 1–3.

## Submission

Commit the updated `app.py`, updated `findings.db`, and a short `browser-confirmation.md` noting what you observed in the real browser (tab title before/after) to `c50-week-05/exercise-03/`.
