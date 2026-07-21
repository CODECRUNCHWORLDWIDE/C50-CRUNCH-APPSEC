# Challenge 2 — Attack Tree for One Attacker Goal

**Time:** ~90 minutes. **Difficulty:** Medium. **A new tool: attack trees, built from threats you already found.**

## Background: what an attack tree adds

STRIDE-per-element is exhaustive but flat — it gives you a long list of individual threats, one per element, with no sense of how several small ones might *combine*. An **attack tree** flips the perspective: instead of "for each element, what could go wrong," you start from **one specific attacker goal** and work backward, asking "what would have to be true for an attacker to achieve *this*?" Children of a node are connected by **AND** (every child must succeed) or **OR** (any one child suffices), and the leaves are the smallest concrete steps — often the exact same threats your STRIDE pass already found, just reorganized around a goal instead of an element.

## Your task

1. **Pick one concrete attacker goal**, stated as a specific, testable outcome — not "compromise the app," but something as precise as *"read another customer's order history in Juice Shop"* or *"grant a non-admin account admin privileges."* Draw it from your own Exercise 2 or Challenge 1 threat list if you can — the goal should be something your STRIDE pass already hinted was possible.

2. **Build the attack tree** as a Mermaid `flowchart`, root node = the goal, with AND/OR branches down to leaf nodes that are concrete, single steps (e.g., "obtain another user's session token," "modify basket price via intercepted request," "reach `/#/administration` directly by URL"). Go at least 3 levels deep on your most interesting branch. Label every AND/OR junction explicitly — don't leave it implicit.

3. **Tie every leaf node to a STRIDE category** — which of the six threat types is this leaf, fundamentally? Most leaves map cleanly to one; if a leaf genuinely spans two, say which is primary.

4. **Tie every leaf node to a detection point** — one concrete thing that could be logged, alerted on, or monitored that would surface an attacker attempting that specific leaf. This is the attacker/defender habit from Week 1, applied at the level of individual attack-tree steps instead of whole threats.

5. **Identify the cheapest defensive cut.** Look at your tree and find the single node whose removal (i.e., whose mitigation) would break the *most* paths to the root — usually a node with many parents, or one high up an AND branch. Write two sentences arguing for that node as the highest-leverage place to spend a defensive effort, even if it doesn't fix every leaf.

## Constraints

- The goal must be **specific and testable** — you should be able to state, in one sentence, exactly what "success" would look like for the attacker, precisely enough that you could (in a later week, with proper scope and authorization) actually verify whether the goal was achieved.
- Every leaf needs both a STRIDE tag and a detection point — a leaf with neither is incomplete.
- No exploitation. This is a design artifact, built from reasoning about your DFD and your existing threat list — not from attempting the attack.

## Hints

<details>
<summary>On choosing the goal</summary>

Strong goals usually sit right at a trust boundary from your Lecture 1/Exercise 1 diagram: "become admin without admin credentials," "read another user's private data," "place an order without paying." Weak goals are too vague to draw a tree from ("hack the site") or too narrow to have any interesting branches ("guess a six-digit code").

</details>

<details>
<summary>On AND vs. OR</summary>

"Reach `/#/administration`" is probably an **OR** node — an attacker might get there by URL-guessing directly, *or* by finding a link, *or* by intercepting an admin's session; any single path suffices. "Forge a valid admin session token" might be an **AND** node if it genuinely requires both discovering the signing algorithm's weakness *and* crafting a payload that passes the server's other checks. Real trees mix both liberally — resist making everything one or the other just because it's simpler to draw.

</details>

## How success is judged

| Signal | Weak submission | Strong submission |
|---|---|---|
| Goal | Vague, or unrelated to anything in your prior threat model | Specific, testable, traceable to a real threat you already found |
| Tree structure | Flat list dressed up as a tree, or AND/OR left unlabeled | Genuine branching, ≥3 levels on the deepest path, every junction labeled |
| STRIDE tagging | Missing or inconsistent | Every leaf tagged, correctly, to the category it fundamentally violates |
| Detection points | Generic ("add logging") | Specific enough that a real engineer could implement it ("alert on >5 failed logins for one account within 60 seconds") |
| Cheapest-cut reasoning | Picks an arbitrary node | Correctly identifies a node whose mitigation breaks multiple paths, with a clear argument why |

## Submission

Commit your tree (Mermaid source + rendered view) and the written reasoning to `week-02-challenges/challenge-02/` in your portfolio.
