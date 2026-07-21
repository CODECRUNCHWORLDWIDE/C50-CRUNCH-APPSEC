# Exercise 2 — Map an Attack Surface

**Goal:** Inventory OWASP Juice Shop's attack surface — every entry point, its trust boundary, and what it exposes — and record it as **queryable rows in SQLite**, not a document you'll never search again.

**Estimated time:** 90 minutes.

## Why a database, not a doc or a spreadsheet

A Markdown list of "things I found" degrades the moment you need to answer a real question: "which entry points accept file uploads?" "which ones have no auth requirement?" "how many did I find last week vs. this week?" A spreadsheet technically answers these with filters, but has no schema, no constraints, no history of who changed what when — and this course's rule holds here as everywhere: **structured findings go in SQL, never a spreadsheet.** A `findings` table gives you real queries, for free, and is the exact tool you'll extend in Exercise 3 and reuse for every findings report through Week 11.

## Setup

```bash
mkdir -p c50-week-01/exercise-02 && cd c50-week-01/exercise-02
python3 -c "import sqlite3; print(sqlite3.sqlite_version)"   # confirm sqlite3 is available
```

Make sure your lab is running (`../exercise-01/lab-setup.sh` if not) and Juice Shop loads at `http://127.0.0.1:3000`.

## Task 1 — Design and create the schema

Create `schema.sql`:

```sql
CREATE TABLE targets (
    target_id     INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,       -- e.g. 'juice-shop'
    base_url      TEXT NOT NULL,
    description   TEXT
);

CREATE TABLE attack_surface (
    entry_id            INTEGER PRIMARY KEY,
    target_id           INTEGER NOT NULL REFERENCES targets(target_id),
    entry_point          TEXT NOT NULL,        -- e.g. '/rest/user/login', 'search box'
    entry_type            TEXT NOT NULL
                              CHECK (entry_type IN
                                ('page','api_endpoint','form_field','file_upload',
                                 'auth_mechanism','cookie_or_session','third_party_integration',
                                 'admin_interface')),
    trust_boundary_crossed TEXT NOT NULL,      -- e.g. 'anonymous -> authenticated', 'user -> admin'
    requires_auth          BOOLEAN NOT NULL,
    accepts_user_input     BOOLEAN NOT NULL,
    notes                  TEXT,
    discovered_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Load it:

```bash
sqlite3 appsec.db < schema.sql
sqlite3 appsec.db "INSERT INTO targets (name, base_url, description) VALUES
  ('juice-shop', 'http://127.0.0.1:3000', 'OWASP Juice Shop, running in the isolated lab from Exercise 1');"
```

## Task 2 — Explore, without exploiting

This is reconnaissance, not attack. You're cataloging what's *there*, the same way you'd inventory a house's doors and windows before deciding which ones need better locks. Spend 45 minutes clicking through Juice Shop as a normal, curious user, and note every place the application:

- Renders a page you can navigate to.
- Accepts text/input from you (search, login, registration, reviews, contact forms).
- Talks to a backend API (open your browser's Network tab / dev tools and watch requests as you click around — this is the single most useful habit for this exercise).
- Involves authentication or sessions (login, "remember me," password reset).
- Looks like it's meant for administrators, not customers.

Juice Shop's product search, login, registration, "Customer Feedback," and basket pages are a good starting set; the browser dev tools' Network tab will show you the underlying `/rest/...` and `/api/...` calls each one makes — record those API endpoints too, not just the pages.

## Task 3 — Record what you found

Write a Python script `record_findings.py` that inserts your discoveries:

```python
import sqlite3
from datetime import datetime, timezone

conn = sqlite3.connect("appsec.db")
cur = conn.cursor()

target_id = cur.execute(
    "SELECT target_id FROM targets WHERE name = ?", ("juice-shop",)
).fetchone()[0]

entries = [
    # (entry_point, entry_type, trust_boundary_crossed, requires_auth, accepts_user_input, notes)
    ("/#/login", "page", "anonymous -> authenticated", False, True,
     "Login form; observed POST to /rest/user/login in Network tab"),
    ("/rest/user/login", "api_endpoint", "anonymous -> authenticated", False, True,
     "Backend auth endpoint; accepts email + password JSON body"),
    ("/#/search", "form_field", "none (public)", False, True,
     "Product search box; query reflected in URL as ?q="),
    ("/rest/products/search", "api_endpoint", "none (public)", False, True,
     "Backend search API called by the search box"),
    ("/#/register", "page", "anonymous -> registered user", False, True,
     "Registration form; security question field looked interesting"),
    ("/#/contact", "form_field", "authenticated -> stored content", True, True,
     "Customer feedback form; likely rendered somewhere later (worth a closer look)"),
    ("/#/administration", "admin_interface", "user -> admin", True, True,
     "Admin panel link found in page source, not in the visible nav menu"),
]

cur.executemany(
    """INSERT INTO attack_surface
       (target_id, entry_point, entry_type, trust_boundary_crossed,
        requires_auth, accepts_user_input, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)""",
    [(target_id, *e) for e in entries],
)
conn.commit()
print(f"Recorded {len(entries)} attack-surface entries.")
conn.close()
```

**Adapt the `entries` list to what you actually found** — the seven above are a starting scaffold to show the shape, not the full answer. A real pass over Juice Shop turns up considerably more (basket/checkout, product reviews, file upload on the profile picture, the forgotten-password flow, and more). Aim for **at least 12 entries** before moving on.

## Task 4 — Query your own findings store

Write and run each in `queries.sql`:

1. **Everything found, newest first.**
2. **Every entry point that does NOT require auth** — the ones a completely anonymous attacker can already reach.
3. **Every entry point that accepts user input AND doesn't require auth** — your highest-attention list, since these are reachable and can carry attacker-controlled data.
4. **Count entries by `entry_type`** — which category has the most entries?
5. **Every entry point where `trust_boundary_crossed` mentions "admin"** — these deserve special scrutiny next week when you threat-model formally.

## Expected result (spot checks)

- Task 4's counts should sum to your total row count in `attack_surface`.
- Task 3's list should include at minimum the login and search endpoints — both unauthenticated and both accepting input.
- Task 5 should return the admin panel entry (and any others you found matching that pattern).

## Done when…

- [ ] `appsec.db` has both tables, with `attack_surface.target_id` correctly enforced as a foreign key (try inserting a row with a bogus `target_id` and confirm SQLite rejects it — you may need `PRAGMA foreign_keys = ON;` first, since SQLite disables FK enforcement by default).
- [ ] At least 12 real attack-surface entries recorded, each with an honest `notes` field (not left blank).
- [ ] All 5 queries in `queries.sql` run and return sensible results.
- [ ] You can explain, from memory, the difference between an entry that "requires_auth" and one that doesn't, and why that distinction changes its risk in Exercise 3.

## Stretch

- Add a `screenshot_path` column and save a screenshot (any tool) for your three most interesting finds, referenced by path.
- Write one query that would have caught the exact IDOR-shaped flaw from Lecture 1 — an authenticated entry point where you'd want to check "does changing an ID let me see something that isn't mine?" — as a candidate list of entries to test more deeply.

## Submission

Commit `schema.sql`, `record_findings.py`, `queries.sql`, and `appsec.db` to your portfolio under `c50-week-01/exercise-02/`. You'll add a `risk` table to this same database in Exercise 3.
