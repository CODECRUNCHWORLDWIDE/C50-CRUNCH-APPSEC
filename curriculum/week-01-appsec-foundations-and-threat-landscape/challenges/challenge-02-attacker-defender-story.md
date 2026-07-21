# Challenge 2 — Attacker/Defender Story

**Time:** ~45 minutes. **Difficulty:** Medium. **No single right answer.**

## The scenario

Lecture 1 introduced the habit this entire course drills: for every attack, hold both sides — how it works, and how you'd detect and stop it. This challenge makes you actually do it, in writing, for one real flaw you observed in your own lab this week.

Pick **one** entry from your Exercise 2 attack-surface inventory or Exercise 3 risk register — something in Juice Shop, DVWA, or WebGoat that you flagged as interesting or risky. You'll tell its story twice.

## Your task

Write `attacker-defender-story.md` with two clearly separated halves, both about the **same single vulnerability**.

### Part 1 — The attacker's story (~250 words)

Write a narrative, in plain prose (not a script or command sequence — save that for Week 3 onward once you've formally studied the technique), from the point of view of someone who found and exploited this weakness. Cover:

- **How they'd find it.** What would lead someone to notice this entry point exists and looks weak? (Reconnaissance, an odd response, a page-source comment, exposed error messages — whatever's plausible for what you actually found.)
- **What they'd try.** In general terms, what makes them suspect this specific weakness, and what's the shape of the test that would confirm it? (Again — describe the reasoning, not a working exploit; you haven't studied the specific technique class in depth yet, that starts Week 3.)
- **What they'd get.** What's the actual outcome if the weakness is real — what data, access, or capability changes hands?
- **Why they'd bother.** Tie this back to Lecture 1's actor types — which kind of attacker would find this specific target worth their time, and why?

### Part 2 — The defender's story (~250 words)

Same vulnerability, opposite chair. Cover:

- **How you'd have caught it before it shipped.** What would a threat model, a code review, or a design decision have needed to ask, to prevent this from ever reaching production? Be specific to *this* flaw, not generic advice.
- **How you'd detect it happening.** What log entry, alert, or anomaly would tell you someone is actively probing or exploiting this right now? If you honestly don't know yet (this is Week 1 — that's expected for some flaw classes), say so and name what you'd need to learn to answer it.
- **How you'd fix it.** What's the actual remediation — described conceptually is fine at this stage, e.g. "add an authorization check that verifies the requester owns this resource" rather than a code diff.
- **What CIA property it protects**, using Lecture 2's vocabulary precisely.

## Constraints

- Both halves must be about the **exact same** finding — not two different vulnerabilities. The value of this exercise is the direct comparison.
- The attacker half stays conceptual — no working exploit code, no step-by-step instructions that would function as a how-to against a real system. You're narrating the *shape* of the attack, not weaponizing it. (You'll build real technique depth, always paired with defense, starting Week 3.)
- Every claim in the defender half must be specific to your chosen flaw — "add input validation" with no detail on *what* input, checked *how*, is too generic to count.

## Hints

<details>
<summary>If your finding is the admin panel discoverable in page source</summary>

Attacker angle: view-source or a directory/asset scan is enough reconnaissance; no special skill required, which affects your likelihood scoring back in Exercise 3. Defender angle: "security through obscurity" (hiding the link) was never the actual control — the real fix is an authorization check on the server side that doesn't care whether the client found the URL by clicking a link or guessing it.

</details>

<details>
<summary>If you're unsure what a real detection would look like</summary>

It's fine, and honest, to write "I don't yet know how to build this alert — it would need logging of [specific event] and a rule that fires when [specific pattern]." Naming the gap precisely is worth more than a vague, confident-sounding non-answer, and previews exactly what Week 9–10's logging and CI/CD security content will teach you to build.

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|----------------|
| Same finding, both halves | Drifts to a different, easier flaw halfway through | Rigorously the same vulnerability throughout |
| Attacker realism | Generic "a hacker would hack it" | Plausible, specific reconnaissance and reasoning tied to what you actually observed |
| Defender specificity | "Add security" | Names the actual design/code/detection change, specific to this flaw |
| CIA precision | Skipped or vague | Correctly names confidentiality, integrity, or availability, with justification |
| Honesty about gaps | Papers over what you don't know | States open questions plainly, rather than faking confidence |

## Submission

Commit `attacker-defender-story.md` to your portfolio under `c50-week-01/challenge-02/`. This two-sided-story habit is the one you'll apply to every OWASP Top 10 category starting next week.
