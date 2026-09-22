# PII-masking bypass in `@safedb/safedb-mcp` via a scalar subquery in the SELECT list

- **Advisory ID:** SANKET-2026-002
- **Package:** [`@safedb/safedb-mcp`](https://www.npmjs.com/package/@safedb/safedb-mcp) (npm) · repo [`narekmalk/safedb-mcp`](https://github.com/narekmalk/safedb-mcp)
- **Affected versions:** ≤ 0.5.0 (latest at time of writing)
- **Fixed version:** none yet — maintainer has acknowledged and a fix is in progress (see *Maintainer status*)
- **Severity:** Medium (~CVSS 3.1 6.5; the reserved CVE record omits a numeric score)
- **Weakness:** CWE-863 (Incorrect Authorization) → exposure of masked personal data (CWE-359)
- **Status:** reported to the maintainer 2026-09-19; acknowledged 2026-09-22; CVE requested from the MITRE CNA-LR (pending)
- **Credit:** Sanket Sarkar — found with [Cutout](https://github.com/Faux16/cutout), a security-testing framework for agentic systems

## Summary

safedb-mcp is a "safe, read-only" MCP database tool that masks sensitive columns (e.g. PII) before
returning rows to an agent, and its README explicitly claims to *"block masked fields selected
through aliases or expressions."* That guarantee can be bypassed: a masked column referenced inside
a **scalar subquery in the SELECT list** is returned in cleartext under the subquery's output alias.

## Proof of concept

Given a masked column `users.ssn`, the following read-only `SELECT` returns the SSN **unmasked**:

```sql
SELECT (SELECT ssn FROM users LIMIT 1) AS x FROM accounts;
-- column "x" comes back with the real ssn value, not the mask
```

Confirmed by driving the package's own `validateReadonlyQuery` + `maskRows` against a local
database (no third-party data touched).

## Root cause

1. **Projection guard misses the subquery scope** — `src/safety/sqlGuard.ts`
   (`resolveColumnLineage` / `collectMaskedColumnRefs`) resolves an *unqualified* column inside a
   scalar subquery against the **outer** query's `FROM` scope rather than the subquery's own, so the
   masked column (`users.ssn`, referenced as bare `ssn` inside the subquery) is never recognized as
   a masked column and the query is admitted.
2. **Masking is keyed on the output column name** — `maskRows` (`src/masking/mask.ts`) decides what
   to mask by the *output* column name via a single `tableHint`, which is dropped when more than one
   table is involved. So the value is returned under the alias `x` with no mask applied.

## Impact

An agent/user who can submit read queries can exfiltrate any masked column (PII, secrets) in
cleartext, defeating the tool's core privacy guarantee. Because safedb-mcp's purpose is to let AI
agents query a database *safely*, untrusted or injected content that reaches the query tool can
drive this bypass.

## Remediation

- **Mask by column lineage, not by output name.** Track each output column back to its source
  table/column and mask based on that lineage, so aliases and expressions cannot strip the mask.
- **Resolve subquery columns in the subquery's own scope** in the projection guard, so masked
  columns referenced inside scalar subqueries are detected.
- Add a regression test for the subquery-in-projection case (and alias/expression variants).

## Maintainer status

Unlike some abandoned packages, this project is **actively maintained**. The maintainer
(narekmalk) acknowledged the report on 2026-09-22, indicated a fix will come as time allows, and
invited a pull request. A fix PR implementing the lineage-based masking is being prepared; this
advisory will be updated with the fixed version once released.

## Related

Independent, novel finding — no prior issue/advisory/CVE for this package at time of writing. It is
an instance of the general "the masking/allowlist guard has a gap" class that recurs across
"safe" data-access MCP servers.

## Timeline

- **2026-09-19** — discovered (found with Cutout); reported to the maintainer by email.
- **2026-09-22** — maintainer acknowledged and invited a fix PR; CVE requested from the MITRE CNA-LR; this advisory published.
