# Week 6 — Quiz

Fifteen questions. Lectures closed. Aim for 13/15 before starting Week 7. A mix of multiple-choice and short reasoning questions — the answer key explains the *why*, not just the letter.

---

**Q1.** Which statement correctly distinguishes authentication from authorization?

- A) They're synonyms; either word works in a design doc.
- B) Authentication answers "who are you"; authorization answers "what are you allowed to do."
- C) Authorization always happens before authentication.
- D) Authentication is only relevant for admin accounts.

---

**Q2.** A route contains only `if "user_id" not in session: return 401`. What has this route verified?

- A) Both authentication and authorization.
- B) Authorization only.
- C) Authentication only — it proves someone is logged in, and says nothing about whether this specific action is permitted for them.
- D) Neither — a session check verifies nothing.

---

**Q3.** Which access-control model is the better fit for "only the CFO role may approve invoices over $10,000, but any authenticated employee may approve invoices under $500"?

- A) Pure RBAC — role alone (`CFO`) already fully captures both rules.
- B) Pure ABAC — attributes (the invoice amount) matter alongside role, so a role check alone can't express the threshold.
- C) Neither model can express a rule involving a numeric threshold.
- D) This requires a new access-control model beyond RBAC and ABAC.

---

**Q4.** What is "role explosion," and what typically causes it?

- A) Too many users assigned to the same role.
- B) Trying to force every fine-grained, per-object or per-attribute rule into new roles instead of using object-level (ABAC-style) checks, causing the role table to grow unmanageably.
- C) A role being deleted while users still hold it.
- D) Roles that grant conflicting permissions to the same user.

---

**Q5.** In `crunch-helpdesk`'s `can_view_ticket(user, ticket)` function from Lecture 1, why must the tenant (`company_id`) check run **before** the ownership check?

- A) It doesn't matter — order is irrelevant as long as both checks exist.
- B) A tenant mismatch must be an absolute floor that no ownership or role match can override; checking ownership first risks accidentally granting access based on an ID collision across companies.
- C) SQLite requires `WHERE` clauses to be evaluated in variable-declaration order.
- D) Ownership checks are always more expensive to compute, so cheaper checks should run last.

---

**Q6.** What makes a direct object reference "insecure"?

- A) The object's ID is stored in the database.
- B) The reference itself (a URL, a form field) being visible to the client.
- C) The server using that client-supplied reference to fetch or modify an object with no check that the requester is actually allowed to access that specific object.
- D) The object having a numeric, rather than alphanumeric, identifier.

---

**Q7.** Why doesn't switching a `ticket_id` from a sequential integer to a random UUID fix an IDOR by itself?

- A) UUIDs cannot be used in SQL `WHERE` clauses.
- B) It removes casual enumeration, but if the server never checks ownership, anyone who legitimately learns one valid UUID (a shared link, a support reply) can still access an object that isn't theirs.
- C) UUIDs are always predictable from the object's creation timestamp.
- D) SQLite doesn't support UUID columns, so this comparison is moot.

---

**Q8.** A route returns `403` when a requested object exists but belongs to someone else, and `404` when it doesn't exist at all. What does this **leak**, and what's the safer alternative?

- A) Nothing is leaked; distinguishing the two cases is a security best practice.
- B) It leaks which object IDs are real (an existence oracle) even though their contents stay hidden; the safer alternative is returning `404` uniformly for both "doesn't exist" and "not yours."
- C) It leaks the requester's own session token.
- D) It leaks the exact SQL query being run.

---

**Q9.** What is the correct one-sentence distinction between horizontal and vertical privilege escalation?

- A) Horizontal escalation crosses company boundaries; vertical escalation never does.
- B) Horizontal escalation accesses another identity's data at the *same* privilege level; vertical escalation reaches a *higher* privilege level than assigned.
- C) They are the same failure, described with two different names.
- D) Vertical escalation only applies to database administrators.

---

**Q10.** `crunch-helpdesk`'s `/admin/users/<id>/promote` route, before it was fixed, allowed a `member` at Company A to promote a user at Company B to `admin`. Which failure shape(s) does this represent?

- A) Horizontal only.
- B) Vertical only.
- C) Both vertical (wrong role reaching an admin-only action) and horizontal (crossing into another company's user record).
- D) Neither — this is a SQL injection vulnerability.

---

**Q11.** Why is "the UI doesn't show that button to this role" not a valid authorization control?

- A) UI code cannot technically hide buttons based on role.
- B) A hidden client-side button is a UI convenience only; a direct request (via `curl`, a modified request, or a proxy) reaches the same server-side route regardless of what the UI renders, so the check must exist on the server.
- C) All users can already see all buttons regardless of role.
- D) Browsers ignore `display: none` styling for buttons specifically.

---

**Q12.** What is the core difference between an "allow-by-default" and a "deny-by-default" route-authorization design?

- A) They behave identically in production; the difference only matters in unit tests.
- B) Allow-by-default requires every route to explicitly add a deny check and fails *unsafe* (silently open) if one is forgotten; deny-by-default requires every route to explicitly declare its required permission and fails *safe* (blocked, caught in testing) if one is forgotten.
- C) Deny-by-default is slower because it always queries the database twice.
- D) Allow-by-default is only a concern for admin routes.

---

**Q13.** In the `before_request` deny-by-default hook from Lecture 3, what happens to a brand-new route added six months from now with no `@require_permission` decorator and not on the public allowlist?

- A) It works normally for every caller, since no specific deny rule targets it.
- B) It returns `403` for every caller, including the developer testing it — turning a potential security bug into an obvious functional bug caught before merge.
- C) It crashes the entire application on startup.
- D) It silently redirects to `/login` regardless of session state.

---

**Q14.** Challenge 2 found that `/tickets/<id>/reassign`, even after an RBAC permission check was added, still had a tenant-isolation gap. What was it?

- A) The route never checked authentication at all.
- B) The route checked that the caller's role could reassign tickets, but never checked that the *ticket* and the *new assignee* both belonged to the caller's own company — two separate identifiers, only one of which had ever been checked.
- C) The route used string-formatted SQL, making it vulnerable to injection.
- D) The route was missing entirely from the application.

---

**Q15.** Why does a systematic role × resource × action test matrix (Exercise 3) prove authorization coverage in a way that manually re-testing "the couple of requests I remember" cannot?

- A) It doesn't — manual spot-checks and a full matrix provide identical coverage.
- B) A matrix enumerates every meaningful combination of role, tenant, and action as data, so gaps show up as specific failing rows instead of depending on a person remembering every combination worth checking, including the ones nobody thought to test manually.
- C) A matrix is required by law for authorization testing.
- D) A matrix only matters for applications with more than 100 users.

---

## Answer key

<details>
<summary>Reveal after attempting</summary>

1. **B** — authentication verifies identity ("who"); authorization verifies permission for a specific action ("what are they allowed to do").
2. **C** — a session check is a complete authentication check and a zero-percent authorization check; it says nothing about whether this particular action, on this particular object, is permitted.
3. **B** — the amount threshold is an attribute of the resource (the invoice), not the requester's role, so ABAC-style attribute logic is needed alongside (or instead of) a pure role check.
4. **B** — role explosion is trying to encode every fine-grained, per-object rule as a new role instead of an object-level (ABAC) check, causing an unmanageable, ever-growing role table.
5. **B** — the tenant boundary must be an absolute floor; checking ownership or role first risks a false match (e.g., a `user_id` that happens to also match an owner ID at a different company) overriding a tenant mismatch that should never be crossed regardless of any other match.
6. **C** — "insecure" describes the missing authorization check on the server, not the reference's visibility or format — the reference itself being client-visible is completely normal and not the flaw.
7. **B** — a UUID stops casual enumeration but the underlying missing ownership check still serves the object to anyone who obtains a valid ID through any legitimate-looking channel; the object-level check is the only real fix.
8. **B** — distinguishing `403` (exists, not yours) from `404` (doesn't exist) creates an existence oracle an attacker can use to map real IDs even without reading their content; uniform `404` for both closes this.
9. **B** — horizontal escalation stays at the same privilege level but reaches another identity's data; vertical escalation reaches a higher privilege level than the account was ever granted.
10. **C** — it's both at once: reaching an admin-only *action* (vertical) against a *different company's* user record (horizontal, in the tenant/object sense) — the two dimensions aren't mutually exclusive and a complete fix must close both.
11. **B** — a hidden button is purely a client-side rendering choice; any direct request to the underlying route bypasses it entirely, so the actual control must live on the server, checked on every request.
12. **B** — allow-by-default silently permits anything not explicitly denied (fails unsafe, discovered by an attacker or an audit); deny-by-default silently blocks anything not explicitly permitted (fails safe, discovered immediately in testing).
13. **B** — the hook blocks any route lacking a declared permission (and not on the explicit public allowlist), returning `403` for everyone, which surfaces as an obvious bug during development rather than a silent security hole in production.
14. **B** — the route checked the caller's role permission but never validated that both the ticket being reassigned and the new assignee actually belonged to the caller's own company — a two-identifier gap, not a missing-authentication or injection issue.
15. **B** — a data-driven matrix turns "did we cover every case" into an enumerable, re-runnable set of rows, catching combinations a person relying on memory or habit would never think to manually re-check.

</details>

**Scoring:** 13+ → start Week 7. 10–12 → re-read the lecture sections behind your misses. <10 → re-read all three lectures from the top; access control is the single most exploited category in real breach data, and this week's habits compound through every remaining week.
