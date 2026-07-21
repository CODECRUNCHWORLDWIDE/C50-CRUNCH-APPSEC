# Challenge 2 — Simulate a Dependency Attack

**Target:** A local, offline package-index scenario you build entirely yourself — no real registry involved at any point.

**Estimated time:** ~90 minutes.

Lecture 3 walked you through a dependency-confusion demo step by step. This challenge asks you to build a **new** scenario from scratch, without the lecture's exact commands in front of you, and then prove the specific defense — hash-pinning — actually stops it. This is the recognition-and-defense skill in the same shape Week 3's Challenge 1 tested against Juice Shop: you've seen the pattern demonstrated once; now build a variant yourself.

## Rules

- Everything stays on `127.0.0.1` or in local directories. No package you build or "attack" in this challenge is ever published to a real index.
- You choose the scenario: it can be a dependency-confusion setup (internal name collides with a higher-versioned "public" impostor) or a typosquat setup (a near-miss name of something you'd plausibly import) — pick whichever teaches you more, and say which one you picked and why in your writeup.
- The "malicious" payload in your impostor package must be a harmless, clearly-labeled print statement or file write to a path inside your own working directory — never anything that touches the network, modifies files outside your lab directory, or does anything you wouldn't want to happen by accident.

## Goal

1. Build two local packages under a colliding or near-miss name (your choice of scenario), one "legitimate," one "impostor," each with distinguishable install-time output.
2. Demonstrate the vulnerable install: show which package actually gets installed when both are reachable, and explain *why* the resolver chose the one it did (version-number comparison, first-index-wins ordering, or another mechanism specific to your scenario).
3. Apply the defense: rebuild your install process using **either** an index-priority fix (dependency confusion) **or** hash-pinning with `pip-compile --generate-hashes` + `pip install --require-hashes` (works for either scenario) — and prove the impostor package is now rejected or unreachable.
4. Log the finding to your `api_findings`/`dependency_findings` database from Exercise 3/Challenge 1, with `asset` naming the specific package name and scenario, and `remediation_summary` describing the exact defense you applied.

## Deliverable

`dependency-attack-sim.md` containing:

1. Which scenario you built (dependency confusion or typosquatting) and why.
2. The exact commands that built both packages and demonstrated the vulnerable install, with real terminal output.
3. The exact commands that applied your chosen defense and proved it worked, with real terminal output.
4. One paragraph: if this had been a real internal package name and a real public registry, what would you additionally need in place (organizational process, not just tooling) to have caught this before it ever reached a developer's laptop?

Plus your logged finding in the database.

## What "great" looks like

| Criterion | Weight | Detail |
|-----------|------:|--------|
| Correct mechanism | 30% | The writeup correctly explains *why* the resolver picked the impostor (not a vague "packages are dangerous" statement) |
| Working demonstration | 25% | Real terminal output showing the vulnerable install actually happening |
| Working defense | 30% | Real terminal output showing the same attack now fails after the fix |
| Process reflection | 15% | The organizational-process paragraph goes beyond "run a scanner" to something a real team would actually adopt |

## Submission

Commit `dependency-attack-sim.md`, both local package source trees, and your updated findings database to your portfolio under `c50-week-09/challenge-02/`.
