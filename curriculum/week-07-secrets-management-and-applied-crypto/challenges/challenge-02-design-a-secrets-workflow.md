# Challenge 2 — Design a Secrets Workflow

**Estimated time:** 2 hours.

Every fix so far this week has been reactive: find a leak, rotate, purge, replace bad crypto. This challenge asks you to design (and partially implement) the thing that prevents next week's leak in the first place — a secrets workflow a real small team could actually run.

## The scenario

A 3-person team runs three services that need secrets:

- **`crunch-api`** — a backend needing a database password and a third-party payment API key.
- **`crunch-worker`** — a background job processor needing the same database password plus its own signing key for internal service-to-service auth.
- **`crunch-ci`** — the CI pipeline (GitHub Actions) that builds and deploys both, and needs a deploy credential plus enough access to inject the *other* two services' secrets at deploy time without ever printing them to a build log.

## Part 1 — Design document

Write `secrets-workflow.md` covering, concretely:

1. **Local development.** How does a developer get working secrets on their laptop without ever touching the real production credentials? (Hint: a `.env.example` with placeholder keys, real dev-only credentials issued per-developer or shared via a team password manager — never production secrets on a laptop.)
2. **CI.** Where do `crunch-ci`'s secrets live, and how do they reach a build job without ever appearing in a log line, a `print()`, or an error traceback? Name the specific mechanism your CI provider offers for this (e.g., GitHub Actions' `secrets` context and masked logging) and its actual limits (what *can* still leak a secret even with masking — e.g., printing it byte-reversed, or splitting it across two log lines).
3. **Production.** Where's the system of record — a vault product, a cloud secrets manager, or (justify explicitly if you choose this) something simpler for a 3-person team? How does each service *fetch* its secrets at startup or deploy time, and what happens if the vault is briefly unreachable when a service restarts?
4. **Rotation plan.** For each of the three secrets in the scenario (DB password, payment API key, internal signing key), write a rotation cadence and an actual cutover mechanism: does the old value stay valid for a grace window while every consumer picks up the new one? Who (or what automation) triggers rotation — a calendar reminder, a scheduled job, an incident?
5. **Break-glass.** If the vault itself is unreachable and a service is down in production right now, what's the documented emergency path to get it running again — and what compensating control (an audit log entry, a follow-up rotation) does that emergency path require afterward, since it necessarily bypasses your normal controls?
6. **Your weak point.** Every design has one. Name yours honestly — the single-person who currently must be reachable to rotate the DB password, the bootstrapping secret that has to exist somewhere to unlock the vault itself, whatever it is for your design — and one mitigation that makes it less bad, even if it doesn't eliminate it.

## Part 2 — Implement a slice of it

Pick **one** piece of your design and actually build it, working code, against this week's lab or a small standalone script:

- A `secrets_loader.py` that reads required secret names from a manifest, fetches them from the environment (standing in for your chosen vault/manager), and **fails loudly with a clear error** listing exactly which secret is missing — rather than starting up with `None` and failing mysteriously three requests later.
- **or** a rotation-check script: given a `secret_findings`-style table (extend `week07.db`) with a `secret_type` and a `last_rotated_at` column, query for every secret whose age exceeds its designed rotation cadence and print a plain-English "these need rotating now" report.
- **or** a masked-logging wrapper: a small logging filter that redacts any string matching your known secret values (or patterns) before a log line is written, and a test proving a secret passed into a log call never appears in the log file's actual bytes.

Whichever you pick, it must run and you must show it working against a real (fake-valued) example.

## Done when…

- [ ] `secrets-workflow.md` answers all six points in Part 1 with specifics — names, mechanisms, and cadences, not "use best practices."
- [ ] The Part 2 implementation runs and you've shown its output against a concrete example.
- [ ] The design explicitly states the assumption that any secret ever committed, printed unmasked, or otherwise exposed is treated as compromised and rotated — not just monitored.
- [ ] You've named your own design's weak point honestly, with a real mitigation, not a hand-wave.

## Submission

Commit `secrets-workflow.md` and your Part 2 implementation (with a short `README.md` explaining which piece you built and how to run it) to your portfolio under `c50-week-07/challenge-02/`.
