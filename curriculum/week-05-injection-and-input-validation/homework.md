# Week 5 — Homework

Five problems, ~4 hours total, spread across the week. All hands-on work happens against your own Crunch Notes instance or small snippets you write yourself — nothing here ever points at a system you don't own.

---

## Problem 1 — Audit code snippets for injection (45 min)

Below are five short, self-contained code snippets (Python and one Java-flavored pseudocode). For each, in `snippet-audit.md`, state: (a) is it injectable, and if so, to which interpreter (SQL, shell, template); (b) if injectable, name the exact input that would break it; (c) if not injectable, name the specific reason it's safe (e.g., "parameterized," "no untrusted data reaches an interpreter here").

```python
# Snippet A
cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))

# Snippet B
cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")

# Snippet C
import subprocess
subprocess.run(["convert", filename, "output.png"])

# Snippet D
os.system("convert " + filename + " output.png")

# Snippet E
return render_template("profile.html", bio=user_bio)   # profile.html contains: <p>{{ bio }}</p>
```

**Deliver** `snippet-audit.md` with all five judged correctly and justified.

---

## Problem 2 — Second-order injection, traced by hand (45 min)

Imagine a signup form that **escapes** (doubles single quotes) a user's display name before the first `INSERT`, so the stored value in the database is the escaped version. Weeks later, an admin dashboard reads that display name back out of the database and drops it directly into a **new** SQL query (a "find all orders for this display name" report) — without escaping it again, because "it's already been escaped once."

In `second-order.md` (~300 words): explain concretely why this can still be exploited, walk through what the attacker's original display name would need to look like for the *second* query to break, and explain why parameterizing **both** queries (not just the first) closes this completely. Tie your answer explicitly to Lecture 2 Section 4.

---

## Problem 3 — Write a CSP policy and explain each directive (45 min)

Crunch Notes currently has no CSP header at all. Write the header value you'd add to every response, and in `csp-policy.md`, justify each directive in one sentence — specifically address: would your policy have blocked VULN #3's `<img src=x onerror=...>` payload? Would it have blocked VULN #7's DOM XSS? Be honest if the answer to either is "no, because..." — CSP has real limits, and Lecture 3 Section 6 already told you what they are.

**Deliver** `csp-policy.md` with the header value and the directive-by-directive justification.

---

## Problem 4 — Fix a template-injection snippet (45 min)

Given this vulnerable pattern (Python/Flask, referencing Lecture 1 Section 4):

```python
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string(f"<h1>Hello, {name}!</h1>")
```

Rewrite it correctly in `ssti-fix.md`, and in 3–4 sentences explain *why* your fix works — specifically, why passing `name` as a template **variable** rather than concatenating it into the template **text** closes the SSTI hole, referencing the distinction Lecture 1 Section 4 draws using Crunch Notes' own `/search` route as the "done right" example.

**Deliver** `ssti-fix.md` with the corrected code and the explanation.

---

## Problem 5 — LDAP injection, reasoned from first principles (60 min)

You won't stand up an LDAP server this week, but you can reason about the bug precisely from Lecture 1 Section 4's example filter: `f"(&(uid={username})(userPassword={password}))"`.

In `ldap-injection.md` (~350 words):

1. Construct a `username` value that would make the filter's logic evaluate to "match any user" regardless of the real password — show the resulting filter string, fully substituted.
2. Explain, in your own words, why LDAP filter metacharacters (`(`, `)`, `&`, `|`, `*`) play the same structural role that `'` and `--` play in SQL.
3. Describe, in general terms (you don't need exact library names), what the equivalent of "parameterized queries" looks like for LDAP — most LDAP client libraries provide an escaping function specifically for filter values; name the property that function needs to have to actually be safe (hint: revisit why ad-hoc escaping fails in Lecture 2 Section 4, and explain why a **library-provided, interpreter-aware** escape function doesn't have that same problem).

**Deliver** `ldap-injection.md`.

---

## Time budget

| Problem | Time |
|--------:|-----:|
| 1 | 45 min |
| 2 | 45 min |
| 3 | 45 min |
| 4 | 45 min |
| 5 | 60 min |
| **Total** | **~4 h** |

After homework, take the [quiz](./quiz.md) and ship the [mini-project](./mini-project/README.md).
