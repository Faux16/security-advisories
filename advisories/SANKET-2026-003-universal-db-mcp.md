# Arbitrary local file read in `universal-db-mcp` via DuckDB `read_text` / `read_blob`

- **Advisory ID:** SANKET-2026-003
- **Package:** [`universal-db-mcp`](https://pypi.org/project/universal-db-mcp/) (PyPI) · repo [`Fashad-Ahmed/universal-db-mcp`](https://github.com/Fashad-Ahmed/universal-db-mcp)
- **Affected versions:** ≤ 1.1.3 (latest at time of writing), when the DuckDB backend is enabled
- **Fixed version:** none yet — reported to the maintainer (see *Maintainer status*)
- **Severity:** High — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (7.1)
- **Weakness:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) → arbitrary file read
- **Status:** reported to the maintainer 2026-09-19; CVE requested from the MITRE CNA-LR (pending)
- **Credit:** Sanket Sarkar — found with [Cutout](https://github.com/Faux16/cutout), a security-testing framework for agentic systems

## Summary

`universal-db-mcp` exposes a read-only `query` tool that executes DuckDB SQL. DuckDB provides
table functions that read arbitrary files from the local filesystem (`read_text`, `read_blob`, …).
The adapter's filesystem denylist (`_DUCKDB_FILESYSTEM_PATTERN` in `adapters/duckdb.py`) blocks
`read_csv` / `read_parquet` / `glob` / `LOAD`, but **does not block `read_text` or `read_blob`** —
so a caller who can submit a query can read any file the server process can access. The tool's
advertised "read-only" posture does not prevent it, because these are read functions.

## Affected configuration

Reproduces when the server is configured with the DuckDB backend (`DUCKDB_PATH` set; an in-memory
database requires `DUCKDB_READONLY=false` to start). The file-reading functions execute regardless
of the DuckDB read-only flag.

## Proof of concept

Through the `query` tool:

```sql
SELECT content FROM read_text('/etc/passwd');
-- also: SELECT content FROM read_blob('<path>');
```

Confirmed non-destructively against a planted canary file (the query returned the canary's unique
contents), with no real data accessed. `read_csv` was refused by the existing denylist while
`read_text` / `read_blob` executed — demonstrating the gap.

## Impact

Arbitrary local file read with the server process's privileges: application secrets, `.env`,
configuration, credential files, source. In a typical deployment the `query` tool is reachable by
the agent/LLM, so untrusted or injected content can drive it — turning a "read-only" database tool
into a file-exfiltration primitive.

## Remediation

- Preferred: disable DuckDB filesystem/external access at the connection level —
  `SET enable_external_access = false;` (blocks the file-reading functions wholesale).
- And/or switch from a denylist to an **allowlist** of permitted SQL constructs; a denylist keeps
  missing functions (`read_text` / `read_blob` today, others tomorrow).
- Run the backend with least privilege so a read cannot reach sensitive files.

## Maintainer status

The project is maintained (author: Fashad Ahmed). The vulnerability was reported to the maintainer
by email on 2026-09-19; this advisory will be updated with the fixed version once released.

## Related

The same class — a "read-only" DuckDB-backed data tool allowing `read_text` / `read_blob` file
reads — is publicly documented in sibling DuckDB MCP servers
([motherduckdb/mcp-server-motherduck#95](https://github.com/motherduckdb/mcp-server-motherduck/issues/95),
[ktanaka101/mcp-server-duckdb#35](https://github.com/ktanaka101/mcp-server-duckdb/issues/35)), and
the DuckDB file-read primitive underlies unrelated CVEs (e.g. CVE-2024-9264). This advisory concerns
the distinct `universal-db-mcp` package, which had no CVE or advisory at time of writing.

## Timeline

- **2026-09-15** — discovered (found with Cutout); CVE requested from the MITRE CNA-LR.
- **2026-09-19** — reported to the maintainer by email.
- **2026-09-22** — this advisory published.
