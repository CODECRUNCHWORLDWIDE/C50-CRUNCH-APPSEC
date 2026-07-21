# Week 2 — Resources

Free, public, no signup unless noted. Read the "required" set; treat the rest as reference you dip into when a specific question comes up.

## Required reading (this week's core)

- **OWASP Threat Modeling Process** — the canonical overview of why and how: <https://owasp.org/www-community/Threat_Modeling_Process>
  *Why: the official framing this whole week is built on.*
- **OWASP Threat Modeling Cheat Sheet** — DFDs, STRIDE, and process guidance in one page: <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
  *Why: the fastest reference to re-check yourself against mid-exercise.*
- **Microsoft — The STRIDE Threat Model** (original source of the mnemonic): <https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)>
  *Why: the primary source; every modern STRIDE writeup, including this course's, traces back to it.*
- **OWASP Risk Rating Methodology** (the likelihood × impact approach in more depth than Lecture 3 has room for): <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
  *Why: a more granular scoring model you can graduate to once the simple 1–5 scale feels automatic.*

## Reference (keep in tabs)

- **Adam Shostack — *Threat Modeling: Designing for Security*** (publisher/author page; the book STRIDE-per-element and "four questions" framing largely comes from): <https://shostack.org/books/threat-modeling-book>
  *Why: the deepest, most practitioner-oriented treatment of this week's whole method.*
- **Adam Shostack — "Threat Modeling: 11 Strategies"** (short primer on scope and depth): <https://shostack.org/resources/threat-modeling>
  *Why: more on the "when to stop" judgment call from Lecture 3, Section 5.*
- **NIST SP 800-30 — Guide for Conducting Risk Assessments**: <https://csrc.nist.gov/pubs/sp/800/30/r1/final>
  *Why: the formal, standards-body version of likelihood/impact scoring, useful once you work in a regulated environment.*
- **Bruce Schneier — "Attack Trees" (1999, the original paper)**: <https://www.schneier.com/academic/archives/1999/12/attack_trees.html>
  *Why: the source for Challenge 2's method, from the person who introduced it to security practice.*

## Tools worth knowing about (optional, not required this week)

- **OWASP Threat Dragon** — free, open-source threat-modeling tool with DFD drawing and STRIDE built in: <https://owasp.org/www-project-threat-dragon/>
  *Why: once Mermaid-by-hand feels slow, this is the natural next tool — same method, a GUI.*
- **Mermaid — flowchart syntax reference** (what you've been writing all week): <https://mermaid.js.org/syntax/flowchart.html>
  *Why: the exact syntax reference for AND/OR attack-tree styling and DFD subgraphs used in this week's diagrams.*

## Your lab targets (from Week 1 — official docs)

- **OWASP Juice Shop — Companion Guide** (architecture, challenge categories, official docs): <https://pwning.owasp-juice.shop/companion-guide/latest/part1/introduction.html>
  *Why: the authoritative reference for exactly what this week's worked examples model.*
- **DVWA — GitHub repository and docs**: <https://github.com/digininja/DVWA>
  *Why: setup and vulnerability-category reference for Challenge 1 if you chose DVWA.*
- **OWASP WebGoat — official docs**: <https://owasp.org/www-project-webgoat/>
  *Why: lesson index and setup reference for Challenge 1 if you chose WebGoat.*

## SQL / Python (same toolchain as Week 1, and every week's data storage from here on)

- **Python `sqlite3` module — official docs**: <https://docs.python.org/3/library/sqlite3.html>
  *Why: the reference for `executemany`, parameterized inserts, and connection handling used in Exercise 3.*
- **SQLite — `CHECK` constraints**: <https://www.sqlite.org/lang_createtable.html#ckconst>
  *Why: the reference behind this week's schema, which uses `CHECK` to enforce valid STRIDE categories and dispositions at the database level, not just in application code.*
- **[C33 Crunch SQL, Week 1](../../../C33-CRUNCH-SQL/curriculum/week-01-relational-model-and-select/)** — if `SELECT`, `WHERE`, and `GROUP BY` in this week's queries felt shaky, this is the fastest way to firm them up.

## Glossary

| Term | Definition |
|---|---|
| **Data-flow diagram (DFD)** | A diagram of a system as external entities, processes, data stores, and data flows between them. |
| **External entity** | A person or system outside your control that sends or receives data. |
| **Process** | Something that does work — transforms, validates, routes, or acts on data. |
| **Data store** | Something that holds data at rest (a database table, file, cache, session store). |
| **Data flow** | Data moving between two elements; drawn as a labeled arrow. |
| **Trust boundary** | A line marking where the level of trust changes — control or privilege changes hands. |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — six threat categories, each violating one security property. |
| **STRIDE-per-element** | The method of checking each DFD element against the STRIDE categories that apply to its type. |
| **Risk** | Likelihood × impact, each scored 1–5 in this course's rubric. |
| **Disposition** | The chosen response to a threat: mitigate, eliminate, transfer, or accept. |
| **Mitigate** | Reduce likelihood or impact with a control; the risk still exists at a lower level. |
| **Eliminate** | Remove the feature or flow that creates the threat entirely. |
| **Transfer** | Shift the risk to a party better positioned to bear it. |
| **Accept** | A documented, deliberate decision to take no further action. |
| **Attack tree** | A goal-rooted diagram of the AND/OR-combined steps an attacker would need to reach a specific outcome. |
| **Penetration testing** | Runtime verification of whether a specific vulnerability actually exists in a running system, under written authorization. |

---

*Broken link? Open an issue or PR.*
