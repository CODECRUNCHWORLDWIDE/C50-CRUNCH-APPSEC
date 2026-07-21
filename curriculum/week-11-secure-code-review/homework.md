# Week 11 — Homework

Five problems, ~4 hours total, spread across the week. These reinforce the lectures with extra reps at each step of the method — entry-point mapping, taint tracing, and findings writing on code beyond `crunch-invoices`, plus one written-explanation problem. Commit each.

All problems assume `crunch-invoices` (baseline + `PR #482` applied) from the [week README](./README.md) unless a problem says otherwise.

---

## Problem 1 — Entry-point and sink inventory on new code (45 min)

Below is a **new**, previously-unseen route, `PR #491`, proposed for `crunch-invoices` — a "quick invoice lookup by customer name" endpoint meant for a support-team dashboard. It has not been reviewed yet.

```python
import subprocess

@app.route("/invoices/lookup")
def lookup_invoice():
    customer = request.args.get("customer", "")
    cmd = f"grep -i '{customer}' invoices_export.csv"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify(matches=result.stdout.splitlines())
```

In `homework-01.md`:

1. Build an entry-point row for this route (method, params, source, login check present or not).
2. Build a sink-catalog row — which category from Lecture 1 Section 3 does `subprocess.run(..., shell=True)` belong to?
3. Name the vulnerability class this introduces (it's a close cousin of Week 5's SQL injection, but a different sink entirely) and give one example payload for the `customer` parameter that would run a second, attacker-chosen command.
4. Write the fix — do **not** use `shell=True` or string-build the command; use `subprocess.run([...], shell=False)` with the customer term as a separate list element, and note why that specific change closes the hole.

---

## Problem 2 — Ten taint-tracing reps (60 min)

For each snippet below, state: **(a)** the source, **(b)** the sink, **(c)** every hop between them, and **(d)** whether a real sanitizer exists on the path, for the specific sink named. Put all ten in `homework-02.md`.

1. `path = request.args.get("file"); open(f"/data/{path}")` — sink: file read.
2. `name = request.form["name"]; db.execute("INSERT INTO t (name) VALUES ('" + name + "')")` — sink: SQL execution.
3. `uid = request.view_args["uid"]; db.execute("SELECT * FROM t WHERE id=?", (uid,))` — sink: SQL execution. (Trick question — is this one tainted *and* dangerous, or tainted and safe? Defend your answer.)
4. `token = request.headers.get("X-Api-Token"); if token == API_TOKEN: ...` — sink: the comparison itself.
5. `url = request.json["callback_url"]; requests.get(url)` — sink: outbound HTTP request.
6. `role = session.get("role", "member"); if role == "admin": delete_everything()` — sink: the privileged action. Is `session.get(..., "member")`'s default value itself a control weakness? Why or why not.
7. `data = request.form["payload"]; obj = pickle.loads(base64.b64decode(data))` — sink: deserialization.
8. `q = request.args.get("q"); template = f"<p>Results for {q}</p>"; return render_template_string(template)` — sink: template rendering.
9. `amount = request.form["amount"]; db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, acct_id))` where `acct_id` comes from `session["account_id"]` — sink: SQL execution (this one's the trap: check `amount`'s type, not just its binding).
10. `key = "hardcoded-key-2019"; sig = hashlib.sha1(key.encode() + msg.encode()).hexdigest()` — sink: the signature generation itself.

---

## Problem 3 — Explain the difference between authentication and authorization findings in writing (30 min)

In `homework-03.md`, in your own words (300 words max):

1. Give a one-sentence definition of each: an authentication finding, and an authorization finding.
2. Using `export_invoices` (this week's lab), explain why its flaw is an authorization finding, not an authentication finding — it does check something, after all.
3. Give one example (not from this course) of a route that could have **both** flaws simultaneously, and explain what fixing only one of the two would still leave broken.

---

## Problem 4 — Write two more findings from Lecture 2's traces (45 min)

Lecture 2, Section 4 traced three independent findings in the download-link routes but only Exercise 3 required writing up one in full. In `homework-04.md`, write the other two, following Lecture 3's exact seven-field template: the hardcoded `SIGNING_KEY` (as its own finding, independent of the MD5 issue) and the non-constant-time `sig == expected` comparison. Assign each a severity from Lecture 3's rubric and justify the cell.

---

## Problem 5 — Sanitizer-or-not drill (40 min)

For each of the following, answer **"real sanitizer, for which specific sink, yes or no — and why"** in `homework-05.md`:

1. `html.escape(comment)` before inserting into an HTML template — real sanitizer against XSS? Against SQL injection if that same escaped string is later used in a query?
2. `os.path.basename(filename)` before `open()` — does this fully close a path-traversal risk, or only reduce it? What payload might still get through if `filename` came with a leading `../../` sequence stripped only by `basename`?
3. `re.sub(r"[^a-zA-Z0-9]", "", user_input)` (strip everything but alphanumerics) before splicing into a shell command — real sanitizer? What legitimate input does this break, and does "breaks legitimate input" matter when judging whether a fix is *correct* versus merely *restrictive*?
4. Casting `amount = float(request.form["amount"])` before an arithmetic operation — real sanitizer against a negative-amount business-logic abuse (e.g., a "negative refund" that credits an account)? What control would actually be needed here, if any, beyond the type cast?

---

## Time budget

| Problem | Time |
|--------:|----:|
| 1 | 45 min |
| 2 | 60 min |
| 3 | 30 min |
| 4 | 45 min |
| 5 | 40 min |
| **Total** | **~3.7 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
