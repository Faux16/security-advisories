# Security advisories

Coordinated vulnerability disclosures by **Sanket Sarkar**, an independent security researcher.
Findings here come from testing open-source software (including MCP servers) and are published as
public references for coordinated disclosure and CVE assignment. Each advisory is reported to the
affected maintainer or, where none is reachable, to the relevant package registry, before or
alongside publication.

## Advisories

| ID | Affected | Type | Severity | Status |
|----|----------|------|----------|--------|
| [SANKET-2026-001](advisories/SANKET-2026-001-postgres-mcp-server.md) | `postgres-mcp-server` (PyPI) ≤ 1.0.1 | Arbitrary local file read (CWE-284 → CWE-22) | High (7.1) | Reported to PyPI security 2026-09-22; CVE requested (MITRE CNA-LR, pending) |
| [SANKET-2026-002](advisories/SANKET-2026-002-safedb-mcp.md) | `@safedb/safedb-mcp` (npm) ≤ 0.5.0 | PII-masking bypass via scalar subquery (CWE-863) | Medium (~6.5) | Reported 2026-09-19; maintainer acknowledged 2026-09-22 (fix PR invited); CVE requested (MITRE CNA-LR, pending) |
| [SANKET-2026-003](advisories/SANKET-2026-003-universal-db-mcp.md) | `universal-db-mcp` (PyPI) ≤ 1.1.3 | Arbitrary local file read via DuckDB read_text/read_blob (CWE-22) | High (7.1) | Reported to maintainer 2026-09-19; CVE requested (MITRE CNA-LR, pending) |

## Contact

Please report responses or questions via GitHub issues on this repository.
