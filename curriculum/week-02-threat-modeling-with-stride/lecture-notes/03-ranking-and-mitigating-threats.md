# Lecture 3 — Ranking & Mitigating Threats

> **Duration:** ~2 hours. **Outcome:** You can score any threat as risk = likelihood × impact on a defensible 1–5 scale, choose one of four dispositions (mitigate, eliminate, transfer, accept) and justify it, store the whole ranked model in SQLite so it's queryable, and know precisely when threat modeling is the right tool versus when penetration testing is.

> **Framing, read first.** This lecture stores and ranks threats that were *identified*, not exploited, against your own isolated lab. The output is a document you could hand to a real development team — that's the whole point of ranking: turning a long list into a short, actionable one.

## 1. Why you can't fix everything, and shouldn't try to

Lecture 2's STRIDE-per-element pass, run honestly across even a small system, produces more threats than any team can fix before the next release. That's expected, not a failure of the method — STRIDE is deliberately exhaustive so that nothing gets skipped by accident. The job of *this* lecture is to take that long, flat list and turn it into a short, ordered one, because an unordered list of forty threats is barely more useful to a development team than no list at all. **Ranking is what turns identification into action.**

The standard formula, and the one this course uses throughout:

```
risk = likelihood × impact
```

Both factors are scored on a simple 1–5 scale. Write the scale down and reuse it — the value of a risk score comes entirely from applying the *same* scale consistently, not from the specific numbers:

| Score | Likelihood means… | Impact means… |
|:-:|---|---|
| **1** | Requires insider access or an already-compromised system to even attempt | Cosmetic; no data or availability affected |
| **2** | Requires significant skill or a narrow, unlikely precondition | Minor data exposure (non-sensitive) or brief, self-healing disruption |
| **3** | Exploitable by a moderately skilled attacker with public tooling | Exposes some sensitive data, or a single user's account/data |
| **4** | Exploitable by an unskilled attacker with a known, public technique | Exposes many users' sensitive data, or a full account takeover |
| **5** | Trivially exploitable, no special access needed, automatable at scale | Full system compromise, mass data breach, or total service outage |

Apply it to two threats from Lecture 2:

- *"Login error messages reveal whether an email is registered"* (Information Disclosure). Likelihood **4** (trivial — just try logging in and read the message), impact **2** (leaks account existence, not account contents). **Risk = 8.**
- *"Admin panel reachable by any logged-in user because the server never re-checks role"* (Elevation of Privilege). Likelihood **5** (as simple as typing a URL — no special tooling), impact **5** (full read access to every customer's data). **Risk = 25.**

Same 1–5 scale, wildly different scores — and that gap is exactly the signal a ranked list is supposed to surface. The broken-access-control threat is not "a bit worse" than the error-message threat; on this scale it's over three times worse, and a team with one sprint of security time should spend it there first.

## 2. Four dispositions: mitigate, eliminate, transfer, accept

A risk score alone doesn't tell a team what to *do*. Every threat, once scored, gets one of four dispositions:

| Disposition | Meaning | When to choose it |
|---|---|---|
| **Mitigate** | Reduce the likelihood or impact with a control, but the underlying risk still exists at a lower level | The default choice for most threats — you can't remove the feature, but you can add a check, a limit, or a validation |
| **Eliminate** | Remove the feature or flow that creates the threat entirely | When the risk outweighs the feature's value, or a simpler design removes the threat surface altogether (e.g., "don't store the field at all" beats "encrypt the field carefully") |
| **Transfer** | Shift the risk to someone better positioned to bear it | Using a managed payment processor instead of storing card numbers yourself; buying cyber-insurance for residual risk; this is common in Week 7's crypto/secrets discussion and Week 9's supply-chain discussion |
| **Accept** | Knowingly do nothing further, because the cost of any control exceeds the risk | Only valid when it's a *documented, deliberate* decision by someone with authority to make it — silent, undocumented acceptance is not a disposition, it's just an unaddressed risk wearing a label |

Applied to the two scored threats above:

- The login error-message threat (risk 8): **mitigate** — return one generic message ("invalid email or password") for both failure cases. Cheap, removes the whole threat class, doesn't change any legitimate behavior.
- The broken admin-panel access control (risk 25): **eliminate** the *vulnerability* by mitigating the *feature* — add a server-side role check that runs on every request to that route, independent of anything the client claims. (You'll implement exactly this control in Week 6.)

Notice **"accept" is not the same as "ignore."** A risk-8 threat a team explicitly decides not to fix this quarter, with that decision written down and revisited next quarter, is a healthy, mature outcome. A risk-25 threat nobody looked at because the list was 40 items long and unranked is the exact failure this whole lecture exists to prevent.

## 3. Connect every threat to one concrete control

A disposition without a specific control is still not actionable. "Mitigate" is a category; "add a server-side role check on every request to `/api/admin/*`, independent of the client's claimed role" is a control someone can actually implement, review, and later verify. For every threat you rank this week, write down:

- **What control**, specifically — not "add security," but "parameterize the SQL query," "rate-limit to 5 attempts per IP per minute," "log the request's IP and timestamp on both login success and failure."
- **Which later week of this course teaches you to build it**, where applicable — this is how a Week 2 threat model turns into a Week 3–11 work plan instead of a document that gets filed and forgotten.

| Threat (from Lecture 2) | Disposition | Control | Course week |
|---|---|---|---|
| Login SQL query built by string concatenation | Mitigate | Parameterized queries / prepared statements everywhere user input reaches SQL | Week 5 |
| Client-suppliable role trusted in JWT | Mitigate | Server derives role from the `users` store on every request; never trusts a client-supplied role claim | Week 6, Week 7 |
| No login attempt logging | Mitigate | Structured audit log of every login attempt (success/failure, timestamp, IP) written to an append-only store | Week 9 |
| Distinct "wrong email" vs. "wrong password" errors | Mitigate | One generic error message for both cases | Week 3 |
| No login rate limiting | Mitigate | Rate limit per account and per source IP | Week 9 |
| Weak/unsalted password hashing | Mitigate | Modern, salted, slow hash (bcrypt/Argon2) for all stored credentials | Week 7 |
| Admin panel missing server-side role check | Mitigate | Deny-by-default authorization check on every privileged route | Week 6 |
| Client-submitted price trusted at checkout | Mitigate | Server re-derives price from the authoritative `products` store; never trusts a client-submitted amount | Week 5, Week 6 |

## 4. Storing the ranked model as data (never a spreadsheet)

Everything above is naturally two tables — elements and the threats attached to them — and once it's two tables, it belongs in a real database, not a spreadsheet someone will eventually mis-sort by the wrong column. This course's rule holds here exactly as it did in Week 1: **queryable findings live in SQLite or Python, never Excel.**

```sql
-- schema.sql
CREATE TABLE elements (
    element_id    INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    element_type  TEXT NOT NULL CHECK (element_type IN
                      ('external_entity','process','data_store','data_flow')),
    trust_zone    TEXT NOT NULL,     -- e.g. 'untrusted', 'authenticated', 'admin'
    description   TEXT
);

CREATE TABLE threats (
    threat_id       INTEGER PRIMARY KEY,
    element_id      INTEGER NOT NULL REFERENCES elements(element_id),
    stride_category TEXT NOT NULL CHECK (stride_category IN
                        ('Spoofing','Tampering','Repudiation',
                         'Information Disclosure','Denial of Service',
                         'Elevation of Privilege')),
    description     TEXT NOT NULL,
    likelihood      INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact          INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score      INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
    disposition     TEXT NOT NULL CHECK (disposition IN
                        ('mitigate','eliminate','transfer','accept')),
    mitigation      TEXT,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN
                        ('open','mitigated','accepted'))
);
```

Load it with Python instead of typing 30 `INSERT` statements by hand — this is the pattern Exercise 3 has you build in full:

```python
import sqlite3

con = sqlite3.connect("threatmodel.db")
con.executescript(open("schema.sql").read())

threats = [
    # (element_id, stride_category, description, likelihood, impact, disposition, mitigation)
    (2, "Elevation of Privilege",
     "Admin panel reachable by any logged-in user; server never re-checks role.",
     5, 5, "mitigate", "Deny-by-default server-side role check on every admin route."),
    (2, "Information Disclosure",
     "Distinct error messages leak whether an email is registered.",
     4, 2, "mitigate", "Return one generic error for both login failure cases."),
]
con.executemany(
    "INSERT INTO threats "
    "(element_id, stride_category, description, likelihood, impact, disposition, mitigation) "
    "VALUES (?,?,?,?,?,?,?)",
    threats,
)
con.commit()
```

And now the whole point of storing it as data: the risk register is a *query*, always current, never stale the way a spreadsheet copy-pasted into a slide deck becomes the moment someone updates one but not the other.

```sql
-- Top 5 risks, open only
SELECT e.name, t.stride_category, t.description, t.risk_score
FROM threats t JOIN elements e ON e.element_id = t.element_id
WHERE t.status = 'open'
ORDER BY t.risk_score DESC
LIMIT 5;

-- Count of open threats by STRIDE category (where is the model weakest?)
SELECT stride_category, COUNT(*) AS open_count
FROM threats
WHERE status = 'open'
GROUP BY stride_category
ORDER BY open_count DESC;

-- Everything disposed as 'accept' — the risks a team is knowingly carrying
SELECT e.name, t.description, t.risk_score
FROM threats t JOIN elements e ON e.element_id = t.element_id
WHERE t.disposition = 'accept';
```

## 5. When to stop — avoiding analysis paralysis

A STRIDE-per-element pass has no natural ending point — you can always go one level deeper, question one more assumption, imagine one more chained scenario. Left unchecked, threat modeling becomes a way to *avoid* shipping a fix, not a way to find one. Three rules keep a pass finite without making it shallow:

1. **Time-box the first pass.** Give yourself a fixed budget (this week: roughly 90 minutes for a Level 1 diagram of Juice Shop's four flows) and stop at the buzzer, even if you feel incomplete. An imperfect model that exists beats a perfect one that's still being drawn next month.
2. **Depth follows risk, not curiosity.** If a Level 1 process's STRIDE pass turns up a risk-25 threat, that's the process worth exploding to Level 2 for a closer look (Lecture 1, Section 4). A process where every threat scored 2–4 doesn't need it. Let Section 1's scoring, not instinct, decide where to go deeper.
3. **A threat model is a living document, not a one-time deliverable.** You don't need to find *everything* in the first pass, because there won't be a last pass — you revisit the model whenever the design changes (a new endpoint, a new trust boundary, a new third-party integration). Treating Week 2's model as "done forever" is itself a threat-modeling anti-pattern; treating it as "good enough to act on, due for revision" is correct.

If you find yourself past two hours still refining the *same* diagram with no new risk-15+ threats appearing, that's the signal to stop, ship the ranked list you have, and let the next real design change trigger the next pass.

## 6. Threat modeling vs. penetration testing — two different questions

Now that you've run the whole method once, the distinction from Lecture 1, Section 1 is concrete enough to state precisely:

| | Threat modeling (this week) | Penetration testing (Week 3 onward) |
|---|---|---|
| **Question answered** | "What *could* go wrong, given how this is designed?" | "Does a *specific* thing actually go wrong, right now, in the running system?" |
| **When it runs** | Design time — before code exists, or whenever the design changes | After something exists to run against |
| **Input** | A diagram and reasoning | A running target and tools/requests against it |
| **Output** | A ranked list of *possible* threats with proposed controls | Confirmed, reproducible findings, with evidence, against *actual* code |
| **Cost of a miss** | Cheap — you find it on paper, fix it before it's built | Expensive — the flaw already shipped; now you're racing a real attacker to find it first |
| **Cost to run** | An hour with a whiteboard | Requires a target, a scope, tooling, and — critically — written authorization (Week 1) |

They're complementary, not competing: this week's threat model *tells Week 3–11 where to point their tools*. "The admin panel's authorization threat scored 25 and is unverified" is exactly the kind of line item that becomes a specific test case once you learn to run one. A team that only threat-models never confirms their fixes actually work; a team that only penetration-tests only ever finds what they happened to think to try, one running system at a time, with no systematic guarantee of coverage. This course teaches both because real AppSec practice needs both.

## 7. Check yourself

- Write the risk formula from memory, and score a threat of your own choosing on the 1–5/1–5 scale, explaining each number in one clause.
- Name all four dispositions and give a one-sentence example of each that is *not* from this lecture.
- Why is "silent, undocumented acceptance" not a valid instance of the Accept disposition?
- Why does a threat model belong in SQLite/Python rather than a spreadsheet, specifically in terms of what a spreadsheet can't do that the two example queries in Section 4 can?
- Give the three rules from Section 5 for knowing when to stop a STRIDE pass, in your own words.
- In one sentence each, state what threat modeling answers that penetration testing can't, and what penetration testing answers that threat modeling can't.

You've now completed the full method: draw the diagram (Lecture 1), enumerate threats systematically (Lecture 2), and rank + store them (this lecture). The exercises this week walk you through doing all three, in order, against Juice Shop yourself.

## Further reading

- **OWASP Risk Rating Methodology (the likelihood × impact approach in more depth):** <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
- **NIST SP 800-30 — Guide for Conducting Risk Assessments:** <https://csrc.nist.gov/pubs/sp/800/30/r1/final>
- **Adam Shostack — "Threat Modeling: 11 Strategies" (short primer on when/how deep):** <https://shostack.org/resources/threat-modeling>
- **Python `sqlite3` module — official docs:** <https://docs.python.org/3/library/sqlite3.html>
