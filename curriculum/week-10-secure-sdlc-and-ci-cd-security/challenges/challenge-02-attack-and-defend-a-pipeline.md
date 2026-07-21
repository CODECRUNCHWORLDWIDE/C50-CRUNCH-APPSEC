# Challenge 2 — Attack and Defend a Lab Pipeline

**Goal:** Exploit a context-expression shell-injection hole (Lecture 2, Section 5) against your own Crunch Deploy pipeline — running entirely locally via `act`, against a simulated event, never a real GitHub repository — then patch it and build a detector that would catch this exact pattern before it does damage.

**Estimated time:** ~90 minutes.

## Why this is still authorized, defensive work

Everything in this challenge runs against **your own** `crunch-deploy` project, on **your own machine**, using `act` to simulate a GitHub Actions event entirely offline. You are not attacking a real GitHub repository, a real workflow, or anyone else's infrastructure — `act` never contacts GitHub at all for this exercise; it reads a JSON file you write yourself and feeds it to a local Docker container standing in for a runner. The technique — a maliciously-crafted issue title breaking out of a `run:` block — is one of the most common real-world causes of CI/CD compromise, which is exactly why you're reproducing it safely here: so you recognize it instantly in a real pipeline and know how to close it before it ships, not after.

## Part A — Add the vulnerable pattern (on purpose, to a branch)

Create a new workflow, `.github/workflows/issue-triage.yml`, that reacts to issue events — a plausible, common real-world automation ("greet new contributors," "auto-label based on title keywords") that also happens to be exactly the shape of the real-world bug:

```yaml
name: Issue Triage

on:
  issues:
    types: [opened]

permissions:
  contents: read
  issues: write

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Greet new issue
        run: echo "Thanks for opening: ${{ github.event.issue.title }}"
```

Commit it locally (still no push, no remote):

```bash
git add .github/workflows/issue-triage.yml
git commit -q -m "Add issue triage automation (contains PIPE-7, fixed later this challenge)"
```

## Part B — Exploit it locally with a crafted event

Build a fake `issues.opened` event payload with a malicious title. Save as `malicious-event.json`:

```json
{
  "action": "opened",
  "issue": {
    "title": "hello\"; echo INJECTED >> /tmp/act-proof.txt; echo \""
  }
}
```

Run it through `act`, simulating the `issues` event:

```bash
rm -f /tmp/act-proof.txt
act issues -e malicious-event.json -P ubuntu-latest=catthehacker/ubuntu:act-latest
cat /tmp/act-proof.txt   # if this file exists and contains "INJECTED", the injection worked
```

**Task 1.** Confirm `/tmp/act-proof.txt` now exists and contains `INJECTED`, proving the crafted issue title broke out of the intended `echo` command and ran an arbitrary second command — inside the simulated runner container, on your own machine, using an event you wrote yourself. Record the exact payload and the proof in `pipeline-injection-log.md`.

**Task 2.** Explain, in `pipeline-injection-log.md`, exactly why this happened: at what point does GitHub Actions substitute `${{ github.event.issue.title }}` into the `run:` block's text, relative to when the shell actually parses that text? (Lecture 2, Section 5 has the answer — restate it in your own words, don't quote it.)

## Part C — Patch it (the real fix, not a workaround)

Fix `issue-triage.yml` using the `env:`-indirection pattern from Lecture 2:

```yaml
      - name: Greet new issue
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: echo "Thanks for opening: $ISSUE_TITLE"
```

**Task 3.** Re-run the exact same attack:

```bash
rm -f /tmp/act-proof.txt
act issues -e malicious-event.json -P ubuntu-latest=catthehacker/ubuntu:act-latest
cat /tmp/act-proof.txt 2>&1   # expect: No such file or directory
```

Confirm the file no longer appears — the shell now sees only `$ISSUE_TITLE` as literal text in the command, with the actual (still malicious-looking) string bound as an environment variable's *value*, never re-parsed as command syntax. Try a second, differently-shaped payload of your own (e.g., one using backticks instead of a semicolon) against the patched workflow and confirm it's blocked too — one payload passing is not proof the *pattern* is closed; try at least two different injection shapes.

## Part D — Build a detector (the defensive half — do not skip)

A patched workflow protects you going forward. It says nothing about whether this pattern exists **elsewhere** in a growing set of workflow files, or whether someone reintroduces it next month in a new automation nobody thought to review as carefully as this one. Build a static check that catches the *pattern* itself, across every workflow file, the same "detect the shape of the bug, not just today's instance" discipline Week 5's blind-injection challenge used.

**Task 4.** Write `detect_context_injection.py`:

```python
import re
import sys
from pathlib import Path

# Matches an unquoted, direct ${{ github.event... }} or ${{ github.head_ref }}
# style interpolation appearing inside a run: block's inline command text --
# a real linter would parse the YAML properly; this regex-based version is
# a deliberately simple, readable stand-in that still catches the pattern.
RISKY_PATTERN = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref)")

def scan_workflow(path: Path) -> list[str]:
    findings = []
    in_run_block = False
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        if re.match(r"\s*run:\s*", line):
            in_run_block = True
        if in_run_block and RISKY_PATTERN.search(line):
            findings.append(f"{path}:{lineno}: {line.strip()}")
        if in_run_block and line.strip() and not line.strip().startswith(("run:", "#")) and "${{" not in line and ":" not in line:
            in_run_block = False  # crude: leaving a multi-line run: block
    return findings


if __name__ == "__main__":
    workflow_dir = Path(".github/workflows")
    all_findings = []
    for wf in workflow_dir.glob("*.yml"):
        all_findings.extend(scan_workflow(wf))
    for f in all_findings:
        print(f)
    sys.exit(1 if all_findings else 0)
```

**Task 5.** Run it against both the vulnerable and the patched version of `issue-triage.yml` (check out each with `git show` into a temp copy, or just re-run against your git history) and confirm it flags the vulnerable version and stays silent on the patched one. Note honestly, in `pipeline-injection-log.md`, what this detector would and would **not** catch — it's a pattern-matcher on `run:` blocks, not a full GitHub Actions expression-language parser, so a payload that reaches a shell through a different mechanism (an `env:` value referenced unsafely inside a *nested* script it calls, for instance) is outside this simple version's reach. Naming a detection tool's limits honestly is the same discipline Week 8's triage funnel required for every scanner.

**Task 6.** Wire `detect_context_injection.py` into `.github/workflows/deploy.yml` itself as an additional gate, right alongside the SAST/SCA gates from Exercise 1 — this is now part of your standard build-failing gate set, not a one-off script you ran once.

## Expected result

- `pipeline-injection-log.md` documents a real, reproduced exploitation of the vulnerable workflow and the exact reasoning behind why the fix closes it.
- The patched workflow blocks at least two differently-shaped injection payloads, not just the original one.
- `detect_context_injection.py` correctly flags the vulnerable pattern and stays silent on the fixed one, and is wired into `deploy.yml` as a gate.

## Submission

Commit `.github/workflows/issue-triage.yml` (patched version), `malicious-event.json`, `pipeline-injection-log.md`, `detect_context_injection.py`, and the updated `deploy.yml` to `c50-week-10/challenge-02/`.
