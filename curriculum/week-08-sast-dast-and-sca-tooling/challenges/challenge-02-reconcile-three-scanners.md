# Challenge 2 — Reconcile Three Scanners

**Time:** ~45 minutes. **Difficulty:** Medium-hard. **No single right answer, but a clear right shape.**

## The scenario

Your Exercise 3 `findings` table holds rows from Semgrep, ZAP, and Trivy, loaded and lightly triaged, but treated as three independent streams. Lecture 3, Section 4 showed how the *same* underlying weakness can surface as zero, one, or several differently-worded findings across tools. Right now, your backlog almost certainly has some genuine duplication hiding in plain sight — and possibly some findings that merely *look* related (they mention the same route, or the same library name) but are actually describing unrelated problems.

Reconciliation is the discipline that turns "three lists" into "one accurate picture of what's actually wrong," and it's exactly the step a real AppSec team does before a findings report ever reaches an engineering manager — nobody wants to see the same bug listed three times with three different severities and no indication they're the same thing.

## Your task

1. **Add a `duplicate_of` column** to your `findings` table if you haven't already (`ALTER TABLE findings ADD COLUMN duplicate_of INTEGER REFERENCES findings(finding_id);`).
2. **Review your full backlog** (`SELECT * FROM findings ORDER BY target_id, file_path, url, package_name;` — sorting by these fields clusters findings that touch the same area of the app next to each other) and identify **at least two genuine cases of cross-tool duplication** — the same underlying weakness, described by two or three different scanners in their own vocabulary.
3. **For each duplicate cluster**, pick one finding as the **canonical** entry (typically the one with the most specific, actionable detail — often the SAST finding, since it names an exact file and line) and set every other finding in the cluster's `duplicate_of` to point at the canonical finding's `finding_id`. Update the canonical finding's `triage_notes` to explicitly list which other `finding_id`s it absorbs and why they're the same weakness.
4. **Find at least one "near-miss"** — two findings that *look* related (share a keyword, a file, a library name) but that you determine, after real investigation, are **not** actually the same weakness — and document, in `reconciliation-log.md`, why you did **not** merge them. This half of the exercise matters as much as the merging half: over-merging hides real distinct problems just as badly as under-merging inflates the count.
5. **Produce the final canonical backlog** with one query:

   ```sql
   SELECT finding_id, rule_id, title, severity_normal, risk_score, status
   FROM findings
   WHERE duplicate_of IS NULL
   ORDER BY
     CASE severity_normal
       WHEN 'critical' THEN 5 WHEN 'high' THEN 4
       WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1
     END DESC,
     risk_score DESC;
   ```

   Save this as `final-backlog-query.sql` and its actual output as `final-backlog-output.txt`.

## Constraints

- Every merge decision needs a **specific, written reason** referencing the actual evidence (matching file paths, matching CVE-to-code-path connections, matching root-cause description) — "these seem related" is not sufficient.
- Every **non-merge** decision (the near-miss from step 4) needs an equally specific reason for *why not*, not just "I decided these were different."
- The canonical finding chosen from each cluster must retain (in its `triage_notes` or `description`) enough detail that someone reading only that one row understands the full picture — don't silently drop useful detail from the findings you mark as duplicates.

## Hints

<details>
<summary>On where real duplication tends to hide</summary>

Look for cases where a Trivy SCA finding names a vulnerable library, and a Semgrep SAST finding separately flags *your code's own usage* of that same library in a way that touches the vulnerable function — these are related but often should stay as **two** findings (the library's bug, and your usage pattern), unless your usage *is* the vulnerable call path, in which case they may genuinely describe one exploitable chain. This is exactly the judgment call Lecture 3, Section 4's JWT example was designed to make you practice.

</details>

<details>
<summary>On the near-miss requirement</summary>

A good near-miss candidate: two findings that both mention "authentication" or "session," or both touch the same route path but describe genuinely different aspects of it (e.g., a DAST alert about a missing security header on `/rest/user/login`, and a separate SAST finding about weak password-hashing logic in the same login handler — related to the same feature, but not the same weakness, and fixing one does nothing for the other).

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|----------------|
| Merge accuracy | Merges findings because they mention the same word | Merges findings with a traced, specific shared root cause |
| Non-merge judgment | No near-miss identified, or a trivial one | A genuine near-miss with a specific reason the two stayed separate |
| Canonical entry quality | Picks an arbitrary finding to keep, loses detail from the others | Canonical entry's notes preserve the useful detail from every absorbed finding |
| Final query correctness | Query includes duplicate rows, or excludes legitimately-canonical ones | `final-backlog-output.txt` shows exactly one row per real, distinct issue |

## Submission

Commit the `ALTER TABLE` statement, `reconciliation-log.md`, `final-backlog-query.sql`, `final-backlog-output.txt`, and the updated `appsec.db` to your portfolio under `c50-week-08/challenge-02/`. The mini-project's final backlog builds directly on this reconciled version — don't start over.
