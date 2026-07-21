# Challenge 1 — Write a Custom SAST Rule

**Time:** ~45 minutes. **Difficulty:** Medium. **No single right answer, but a clear right shape.**

## The scenario

Generic rulesets like Semgrep's `auto` config are trained on patterns that are dangerous *in general* — raw SQL concatenation, `eval` on user input, hardcoded secrets. They cannot know about a pattern that's dangerous specifically *in your app*, because it doesn't exist anywhere else. A rule Exercise 1's `auto` scan won't write for you: "this specific internal helper function is our app's own designated sink, and any untrusted data reaching it unsanitized is a real bug here, even though the function itself is nothing Semgrep has ever seen before."

This challenge has you find (or construct) exactly that kind of app-specific pattern, and write, test, and prove a rule for it — the actual skill a security engineer embedded on a real team uses constantly, because most of the interesting vulnerable patterns in a mature codebase are ones nobody outside that team could have written a generic rule for.

## Your task

1. **Find or construct an app-specific vulnerable pattern.** Either:
   - Search Juice Shop's source (`c50-week-08/exercise-01/juice-shop-src/`) for a genuine pattern the `auto` ruleset in Exercise 1 did **not** flag but that you believe represents a real risk given what you traced by hand in that exercise's Task 3, **or**
   - Construct a small, realistic synthetic example (10–20 lines) representing a pattern specific to *how a hypothetical app you're securing* uses a particular internal function — e.g., a custom `renderUserBio(html)` templating helper that's safe when called with server-generated content but dangerous when called with raw user input, a distinction no generic XSS rule would know about without being told.
2. **Write the rule** as `custom-rule.yaml`, following the anatomy from Lecture 1, Section 5 — a real `id`, `message`, `severity`, `metadata` (CWE/OWASP tags), and a `patterns`/`pattern-either`/`pattern-not` (or full taint-mode `pattern-sources`/`pattern-sinks`) block that captures the specific dangerous shape.
3. **Prove it two ways**, saved as `test-vulnerable.js` (or `.ts`) and `test-safe.js`:
   - Run `semgrep --config=custom-rule.yaml test-vulnerable.js` — it **must** report a finding.
   - Run `semgrep --config=custom-rule.yaml test-safe.js` — a variant using the same function but through the safe path (sanitized, or the internal-only call site your rule should tolerate) — it **must** report zero findings.
4. **Write `rule-rationale.md`** (~250 words) explaining: what the app-specific pattern is, why a generic ruleset couldn't have caught it, and what a developer should do differently when the rule fires.

## Constraints

- The rule must be **narrow enough that it wouldn't also fire on unrelated, safe code** — a rule so broad it flags half the codebase isn't a useful custom rule, it's noise with your name on it. Prove this by running it against the *entire* Juice Shop source tree and confirming the finding count is small and every hit is genuinely relevant, not just running it against your two isolated test files.
- Your `test-safe.js` variant must be a **real, meaningfully different safe path**, not a trivial rename of the vulnerable variant — the point is testing that your rule's `pattern-not` or sanitizer-recognition logic actually works, not just that the rule matches literal strings.

## Hints

<details>
<summary>On finding a genuine app-specific pattern in Juice Shop</summary>

Juice Shop deliberately includes several intentionally-vulnerable patterns that are specific to *how this particular app* structures its code — for instance, look at how search/feedback/review features handle user-supplied strings before they reach rendering or storage, and whether any internal helper functions exist that aren't generic dangerous APIs (like `eval`) but are still, in this app's specific usage, effectively a sink. A pattern is "app-specific" if a rule for it would be meaningless copy-pasted into an unrelated codebase.

</details>

<details>
<summary>On taint-mode vs. simple pattern rules</summary>

Section 5's example used a plain `pattern`/`pattern-not` rule, which is enough for a narrow, single-hop check. If your app-specific pattern involves data flowing through an intermediate variable or function call before reaching the sink (the way Lecture 1, Section 2's multi-hop example did), you'll get a more robust rule using Semgrep's `mode: taint` with explicit `pattern-sources`/`pattern-sinks`/`pattern-sanitizers` blocks — see the Semgrep taint-mode docs in `resources.md` if your first attempt with plain patterns feels fragile.

</details>

## How success is judged

| Signal | Weak answer | Strong answer |
|--------|-------------|----------------|
| Pattern specificity | A rehash of a generic rule already in `auto` (e.g., re-detecting plain `eval`) | A genuinely app-specific shape no generic ruleset would know to look for |
| Proof of correctness | Asserts "this rule works" with no test run shown | Both `test-vulnerable.js` (fires) and `test-safe.js` (silent) actually run, with output pasted or screenshotted in `rule-rationale.md` |
| Precision | Rule is so broad it also flags unrelated code when run against the full source tree | Rule fires only on genuinely relevant matches when run against the full tree, with the count and a spot-check reported |
| Rationale | "This is bad because it could be exploited" | Explains the specific data flow, why a generic tool can't see it, and what a developer should do when the rule fires |

## Submission

Commit `custom-rule.yaml`, `test-vulnerable.js`, `test-safe.js`, and `rule-rationale.md` to your portfolio under `c50-week-08/challenge-01/`. The mini-project requires exactly this deliverable, wired into the same pipeline as your Exercise 1 scan — bring this rule forward rather than starting a new one.
