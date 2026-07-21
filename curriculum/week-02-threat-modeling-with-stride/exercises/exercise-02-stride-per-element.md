# Exercise 2 — STRIDE-per-Element Pass

**Goal:** Run the full STRIDE-per-element method from Lecture 2 against every element on **your own** diagram from Exercise 1, producing a specific, named threat list — not a copy of Lecture 2's worked examples.

**Estimated time:** 90 minutes.

## Setup

Have `dfd.md` from Exercise 1 open beside you. If you haven't finished Exercise 1, finish it first — this exercise has no diagram of its own to work from.

## Tasks

1. **List every element on your diagram** in a table with two columns: element name, element type (external entity / process / data store / data flow).

2. **For each element, look up its STRIDE row** from Lecture 2, Section 2 — write down which letters apply *before* you start asking questions, so you don't accidentally check Spoofing against a data store.

3. **Run the applicable questions against every element**, and for every "yes, plausibly," write one threat as a single sentence in this exact shape:

   > *"[Actor/mechanism] can [violate property] on [element], via [specific flow/mechanism]."*

   Example shape (don't copy Lecture 2's actual content — use your own observations from Exercise 1):
   > *"An attacker with a stolen session token can impersonate the customer, because the token isn't bound to any other verifiable signal."*

4. **Aim for a minimum of 15 threats total**, spread across at least four different STRIDE categories and at least four different elements. If you find yourself stuck on one element for more than 10 minutes, move to the next — you can return.

5. **For each threat, add a one-clause mitigation direction** in parentheses, the way Lecture 2 modeled — you don't need full detail yet (that's Exercise 3/Lecture 3), just a plausible direction.

6. **Flag your single scariest threat** — the one you'd fix first if you had one hour — and write two sentences explaining why, in plain language, as if explaining it to a non-security teammate.

## A pointed prompt for the admin panel

Whatever you observed in Exercise 1 Task 4 (does the server actually block non-admins, or only the UI?) should directly shape at least one Elevation of Privilege threat here. If your observation showed the server-side check is missing or the client-side redirect can be bypassed by navigating directly to the URL, that is your single highest-value threat this exercise — don't undersell it in your writeup.

## Deliverable

A file `stride-pass.md` containing:
- The element table (Task 1).
- Your full threat list (Task 3–5), grouped by element, each threat as one sentence + one mitigation clause.
- The Task 6 flagged threat and its two-sentence justification.

## Done when…

- [ ] Every element from your Exercise 1 diagram appears, with the correct STRIDE letters checked for its type (no Spoofing checked against a data store, no Elevation of Privilege checked against a data flow).
- [ ] At least 15 threats total, across at least 4 STRIDE categories and 4 elements.
- [ ] Every threat names a *specific* element and mechanism — "the login process is insecure" is not a threat statement; "an attacker can enumerate valid emails via distinct error messages on the login process" is.
- [ ] Every threat has a mitigation-direction clause attached.
- [ ] One threat is explicitly flagged as the scariest, with a plain-language justification.

## Stretch

- For your flagged scariest threat, sketch (in one or two sentences) what a *chained* threat would look like — what a second, unrelated threat on your list would let an attacker combine with it for a worse outcome. (This is a preview of Challenge 2's attack trees.)

## Submission

Keep `stride-pass.md` in `week-02-exercises/exercise-02/` in your portfolio. Exercise 3 loads this threat list into a database.
