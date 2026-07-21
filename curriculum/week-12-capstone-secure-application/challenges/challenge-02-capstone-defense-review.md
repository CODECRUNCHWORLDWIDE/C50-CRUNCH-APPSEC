# Challenge 2 — Defend Your Design

Every other challenge and exercise this course has asked you to find, fix, and prove. This one asks you to **explain** — to stand behind your capstone in front of someone who did not watch you build it, who will ask "why" until your answer either holds or doesn't. This is the format a real security design review takes, and it's the format the mini-project's final deliverable will be judged against.

**Estimated time:** 90 minutes.

## The setup

Find a reviewer — a classmate, a mentor, a study-group partner, or, if none is available, record yourself answering out loud and re-listen critically. Give them nothing but your `SCOPE.md`, `THREAT-MODEL.md`, and `capstone_findings.db` in advance — no verbal walkthrough first. The review starts cold, the way a real one would.

## The questions you must be ready to answer

Your reviewer should ask (or you should ask yourself, honestly) every one of these:

**On scope and threat model:**
1. "Show me your scope document. What's explicitly out of scope, and why?"
2. "Walk me through your data-flow diagram. Where are the trust boundaries, and what changes at each one?"
3. "Give me one STRIDE finding from your table that a scanner could never have found. Why not?"

**On the build:**
4. "Pick any one of your fixes — not the easiest one — and explain why it closes the whole *class* of bug, not just the one line that was flagged."
5. "If I changed one thing about your threat model — say, added a second company sharing this app, like Week 6's multi-tenant scenario — which of your current fixes would break, and why?"

**On findings and remediation:**
6. "Show me a finding you marked `wont_fix` or `accepted`. Convince me that's the right call, not a shortcut."
7. "What's the one finding in your whole capstone you're least confident is actually fixed? Why that one?"

**On residual risk:**
8. "If you had to ship this app to real users tomorrow, what's the one thing you'd fix first that you didn't get to this week — and what's the one thing you'd explicitly flag as a known, accepted gap in the release notes?"

## Producing the residual-risk sign-off

After the review (whether live, with a partner, or self-conducted), write `RESIDUAL-RISK.md`: a short, honest statement of what ships with known, accepted risk, and why that's a defensible decision rather than an oversight. This is not a confession of failure — every real piece of shipped software carries some accepted risk, explicitly or not. The difference between a professional and an amateur is that the professional's is written down, sized, and owned.

```markdown
# Residual Risk — Crunch Ledger Capstone

As of <date>, the following risks are known, accepted, and not fixed in this release:

1. **<risk>** — likelihood: <l>, impact: <i>. Accepted because <reasoning>.
   Revisit if: <the condition that would change this decision>.
2. ...

All other findings identified during this capstone (threat model, SAST, DAST, SCA,
and manual review) are fixed and re-tested; evidence is in capstone_findings.db.
```

## Done when…

- [ ] You (or your reviewer) can answer all eight questions above without needing to open the code mid-answer — the reasoning should already live in your head, not just in the files.
- [ ] `RESIDUAL-RISK.md` exists, lists at least one real accepted risk (not "none — everything is fixed," which is rarely true and reads as unexamined rather than thorough), and each entry has a concrete "revisit if" condition.
- [ ] If you used a live reviewer, you have at least one note on a question you answered less confidently than you'd like — and a sentence on what you'd do to shore it up.
- [ ] You can state, in one sentence, the single design decision in Crunch Ledger you're proudest of defending — and the single one you're least sure about.

## Why this one is different

Every other assignment this course has a clear pass/fail signal: the exploit works or it doesn't, the query returns the right rows or it doesn't. A design defense doesn't work that way — the signal is whether your reasoning holds up to a stranger's honest skepticism, which is exactly the situation a real code review, a real security audit, or a real incident post-mortem puts you in. If Challenge 1 proved you can close what you find, this challenge proves you can be trusted to say, out loud and specifically, what you didn't close and why that's still a responsible way to ship.

## Submission

Commit `RESIDUAL-RISK.md` and, if you recorded or wrote up the review conversation, a short `defense-notes.md` to `c50-week-12/challenge-02/`. The mini-project's final package assembles this alongside every other artifact from the week into one deliverable.
