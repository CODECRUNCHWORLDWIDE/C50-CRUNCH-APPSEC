# Exercise 3 — Build a Risk Register

**Goal:** Extend Exercise 2's SQLite database with a proper **risk register** — assets, threats, and likelihood × impact scores tied back to your attack-surface findings — and query it to answer the question every security program actually runs on: **what do I fix first?**

**Estimated time:** 90 minutes.

## Setup

Use the same `appsec.db` from Exercise 2 — this exercise adds tables and data to it, it doesn't start fresh.

```bash
cd c50-week-01/exercise-02   # or wherever your appsec.db lives
sqlite3 appsec.db "PRAGMA foreign_keys = ON;"
```

## Task 1 — Design and create the risk-register schema

Add three tables to `appsec.db` (put this in a new `risk-schema.sql` and load it):

```sql
CREATE TABLE assets (
    asset_id     INTEGER PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(target_id),
    name         TEXT NOT NULL,          -- e.g. 'Customer accounts + PII'
    description  TEXT
);

CREATE TABLE threats (
    threat_id    INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,           -- e.g. 'Opportunistic automated scanner'
    description  TEXT
);

CREATE TABLE risks (
    risk_id       INTEGER PRIMARY KEY,
    entry_id      INTEGER REFERENCES attack_surface(entry_id),  -- links back to Exercise 2
    asset_id      INTEGER NOT NULL REFERENCES assets(asset_id),
    threat_id     INTEGER NOT NULL REFERENCES threats(threat_id),
    vulnerability TEXT NOT NULL,           -- what's actually weak, in your own words
    cia_property  TEXT NOT NULL
                    CHECK (cia_property IN ('confidentiality','integrity','availability')),
    likelihood    INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact        INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score    INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
    justification TEXT NOT NULL,           -- why these two numbers, in one or two sentences
    scored_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

The `risk_score` column is a **generated column** — SQLite computes and stores `likelihood * impact` automatically; you never insert it directly and it can never drift out of sync with the two inputs. (If your SQLite build is older than 3.31 and doesn't support generated columns, compute `likelihood * impact` in your `SELECT`s instead — functionally identical, just not stored.)

## Task 2 — Populate assets and threats

```sql
INSERT INTO assets (target_id, name, description) VALUES
  (1, 'Customer account credentials', 'Emails, password hashes, session tokens for all registered users'),
  (1, 'Customer order & payment data', 'Order history, saved addresses, payment-related fields'),
  (1, 'Product catalog integrity', 'Prices, stock, and product descriptions shown to all customers'),
  (1, 'Administrative access', 'The admin panel and any privileged backend operations');

INSERT INTO threats (name, description) VALUES
  ('Opportunistic automated scanner', 'Internet-wide bots probing for common misconfigurations and known-vulnerable patterns, no specific target chosen'),
  ('Financially motivated attacker', 'Seeks data to resell or accounts/payment info to abuse directly'),
  ('Curious authenticated user', 'A legitimate account holder who tries changing IDs or parameters to see what they can reach beyond their own data'),
  ('Malicious insider', 'Someone with some legitimate access who abuses it beyond its intended scope');
```

## Task 3 — Score at least 8 risks from your Exercise 2 findings

For at least 8 rows in your `attack_surface` table, reason through Lecture 2 Section 6's chain — asset, threat, vulnerability, CIA property, likelihood, impact — and insert a scored row. Two full worked examples to match the pattern (adapt IDs to your actual data):

```sql
-- Example 1: the unauthenticated login endpoint, targeted by credential attacks
INSERT INTO risks
  (entry_id, asset_id, threat_id, vulnerability, cia_property,
   likelihood, impact, justification)
VALUES
  (2, 1, 2,
   'Login endpoint has no visible rate limiting or account lockout observed during exploration; a credential-stuffing attempt would not obviously be throttled',
   'confidentiality',
   4, 4,
   'Likelihood 4: credential stuffing against login endpoints is one of the most common automated attacks on the internet, requiring no special access. Impact 4: successful compromise exposes the full account (order history, saved address, payment fields) for every credential pair that succeeds.');

-- Example 2: the admin panel found via page source, not linked from the nav
INSERT INTO risks
  (entry_id, asset_id, threat_id, vulnerability, cia_property,
   likelihood, impact, justification)
VALUES
  (7, 4, 3,
   'Admin panel URL is discoverable in page source and reachable without any check confirming the requester is actually an administrator (to be confirmed with real testing in later weeks; recorded here as a hypothesis worth prioritizing)',
   'confidentiality',
   3, 5,
   'Likelihood 3: requires finding the URL first (moderate effort, not zero), but no special tooling once found. Impact 5: administrative access is the highest-value target on this application by definition — full compromise if the hypothesis holds.');
```

Insert **6 more**, covering a mix of CIA properties and a mix of scores — don't score everything as "High," that defeats the point of a register that helps you prioritize.

## Task 4 — Query the register for prioritization

Write and run each in `risk-queries.sql`:

1. **The full register, highest risk first** — `entry_point`, `vulnerability`, `cia_property`, `likelihood`, `impact`, `risk_score`, ordered by `risk_score DESC`. (Join `risks` to `attack_surface` to get `entry_point`.)
2. **Everything in the Critical band (16–25)** — what would you stop and fix today?
3. **Average risk score per CIA property** — is this application's biggest exposure to confidentiality, integrity, or availability?
4. **Every risk tied to the "Administrative access" asset**, regardless of score — a focused view for one asset, the kind a stakeholder who owns that asset would ask for.
5. **A "fix-first" report**: `entry_point`, `vulnerability`, `risk_score`, and `justification`, for the top 5 by score — this is literally the first artifact of a real findings report, the shape you'll formalize in Week 11.

## Expected result (spot checks)

- Task 1 output is sorted with your highest `risk_score` row on top.
- Task 2 should return only rows where `likelihood * impact >= 16` — if it returns everything or nothing, your scores aren't varied enough; go back and re-score with real differentiation.
- Task 3's three averages should not all be identical — if they are, you haven't actually distinguished CIA properties in your `vulnerability`/reasoning.

## Done when…

- [ ] `risks`, `assets`, `threats` tables exist in `appsec.db`, all foreign keys enforced (`PRAGMA foreign_keys = ON;` at the top of your session).
- [ ] At least 8 scored risks, each with a `justification` that states *why* those specific numbers (not just "seems bad, 4/5").
- [ ] At least two different `cia_property` values represented, and scores that actually vary (not all 4s and 5s).
- [ ] All 5 queries in `risk-queries.sql` run and produce a genuinely prioritized, defensible list.
- [ ] You can explain why `risk_score` is a **generated** column rather than a value you insert by hand.

## Stretch

- Add a `risk_band` computed value (via a `CASE` in your queries, or a view) that labels each row Low/Medium/High/Critical per Lecture 2's bands, so `SELECT * FROM risks_with_band WHERE risk_band = 'Critical'` reads naturally.
- Write a query that finds any `attack_surface` entries from Exercise 2 that have **no** matching row in `risks` yet — your "not yet triaged" backlog, the same gap every real security program has to actively manage.

## Submission

Commit `risk-schema.sql`, the populated `appsec.db`, and `risk-queries.sql` to your portfolio under `c50-week-01/exercise-03/`. This register is your mini-project deliverable — extend it there, don't start over.
