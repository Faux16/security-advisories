# Arbitrary local file read in `postgres-mcp-server` (PyPI) via the read-only `query` tool

- **Advisory ID:** SANKET-2026-001
- **Package:** [`postgres-mcp-server`](https://pypi.org/project/postgres-mcp-server/) (PyPI, Python)
- **Affected versions:** all released versions — `1.0.0` and `1.0.1` (latest)
- **Fixed version:** none (unmaintained; see *Maintainer status*)
- **Severity:** High — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (7.1)
- **Weakness:** CWE-284 (Improper Access Control) → CWE-22 (arbitrary file read)
- **Status:** reported to PyPI security 2026-09-22; CVE requested from the MITRE CNA-LR (pending)
- **Credit:** Sanket Sarkar — found with [Cutout](https://github.com/Faux16/cutout), a security-testing framework for agentic systems

## Summary

`postgres-mcp-server` exposes an MCP `query` tool documented as *"Run a read-only SQL query … SELECT statements only … safely."* Its **entire** validation is a first-word check —
`sql.strip().upper().startswith("SELECT")` — run inside a `READ ONLY` transaction
(`set_session(readonly=True)` / `BEGIN TRANSACTION READ ONLY`). It places **no restriction on
which functions a SELECT may call.** PostgreSQL's built-in file-access functions
(`pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file`) are *reads*, so they satisfy
both the "starts with SELECT" rule and the read-only transaction. A caller who can submit a query
therefore reads any file the database process can access. "Read-only" bounds writes, not reads.

## Proof of concept

Via the `query` tool:

```sql
SELECT pg_read_file('/etc/passwd');
-- also: SELECT pg_ls_dir('/etc');
--       SELECT pg_read_binary_file('<path>');
```

Confirmed non-destructively end-to-end through the MCP `query` tool against a throwaway local
PostgreSQL cluster: a planted canary file was returned by its unique token, `/etc/passwd` returned
its real contents, and `pg_ls_dir('/etc')` returned the directory listing. A write (`INSERT …`) was
correctly refused — showing the guard stops writes but not file **reads**.

## Impact

Arbitrary local file read with the server process's privileges: application secrets, `.env`,
configuration, credential files, the database's own configuration, SSH keys, source. In a typical
deployment the `query` tool is reachable by the agent/LLM, so untrusted or injected content can
drive it — turning a "safe, read-only" database tool into a file-exfiltration primitive.

**Precondition:** the PostgreSQL role the server connects as must have filesystem privileges — the
default `postgres` superuser, or any role granted `pg_read_server_files` (and, for some functions,
`pg_monitor`). This is common where an MCP server is pointed at a database using an administrative
role.

## Remediation (for operators)

- Do **not** treat "starts with SELECT" or a read-only transaction as a security boundary against
  agent-generated SQL. A read-only SELECT can still read files and list directories.
- Run the MCP server against a **least-privilege** PostgreSQL role that lacks
  `pg_read_server_files` / `pg_monitor` / superuser, so these functions are denied at the DB layer.
- Restrict which clients/agents can reach the MCP server (network + auth).

## Remediation (for a maintainer, if the package is revived)

Reject the dangerous built-ins — at minimum `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`
(and its fixed-subdir siblings `pg_ls_tmpdir`/`pg_ls_logdir`/`pg_ls_waldir`), `pg_stat_file`,
`lo_import`/`lo_export`, `dblink*`, and `COPY … TO/FROM (PROGRAM)`. Prefer parsing the statement and
**allowlisting** permitted constructs over a denylist (a denylist keeps missing functions).

## Maintainer status

The package appears **unmaintained with fabricated provenance**: its declared repository
`github.com/mcp-community/postgres-mcp-server` returns 404, its author email (`community@mcp.dev`)
and homepage (`modelcontextprotocol.io`, the official Model Context Protocol site — this is **not**
an official MCP project) are not associated with a reachable maintainer, and the `mcp-community`
GitHub organization (created 2021, before MCP existed) does not host the project. The issue was
therefore reported to **PyPI security** on 2026-09-22.

## Related

The same class — a "read-only" PostgreSQL MCP server allowing `pg_read_file` — is documented as
**CVE-2026-85620** in a *different* package (`crystaldba/postgres-mcp`, via a different bypass).
This advisory concerns the distinct `postgres-mcp-server` package, which has no CVE at time of
writing.

## Timeline

- **2026-09-22** — discovered; reported to PyPI security; CVE requested from the MITRE CNA-LR; this advisory published.
