# Features Roadmap

This document tracks implemented and planned Argus features for security scanning, CI/CD, database security, and remediation.

Related GitHub issues: [#32](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/32), [#33](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/33), [#30](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/30).

---

## Implemented (this release)

### 1. GitHub Action + SARIF export (#32, #33)

| Item | Location |
|------|----------|
| SARIF 2.1.0 formatter | `packages/python/src/argus/formatters/sarif.py` |
| CLI `--format sarif` | `argus scan … --format sarif -o results.sarif` |
| MCP `format: sarif` | `scan_sast`, `scan_all`, `get_scan_report` |
| GitHub workflow | `.github/workflows/argus-sarif.yml` |

**Usage in CI:**

```yaml
- run: pip install -e packages/languages && pip install -e packages/python
- run: argus scan code . --format sarif -o argus.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
    category: argus
```

Findings appear in the GitHub **Security → Code scanning** tab.

---

### 2. `.argus.yml` policy file

| Item | Location |
|------|----------|
| Policy loader | `packages/python/src/argus/policy.py` |
| Example config | `.argus.yml.example` |

**Supported keys:**

| Key | Description |
|-----|-------------|
| `fail_on` | Exit 1 on `critical` / `high` / `medium` / `low` / `never` |
| `min_severity` | Hide findings below this severity |
| `exclude_paths` | Glob patterns to skip |
| `tools` | Limit external scanners |
| `semgrep.config` | Semgrep ruleset (e.g. `p/owasp-top-ten`) |
| `baseline` | Path to baseline JSON for diff |
| `fail_on_new_only` | Only fail on findings not in baseline |
| `suppressions` | Rule/path suppressions with optional `expires` |

**Example:**

```yaml
fail_on: high
exclude_paths:
  - "tests/fixtures/**"
semgrep:
  config: p/owasp-top-ten
suppressions:
  - rule_id: bandit.B101
    path: "tests/**"
    reason: "asserts in tests"
    expires: "2026-12-31"
```

Copy `.argus.yml.example` to `.argus.yml` in your repo root. Argus auto-discovers it when scanning.

CLI override: `argus scan all . --policy path/to/.argus.yml`

---

### 3. `compare_scans` / baseline diff

| Item | Location |
|------|----------|
| Diff engine | `packages/python/src/argus/compare.py` |
| CLI | `argus compare baseline.json current.json` |
| MCP tool | `compare_scans` |

**CLI examples:**

```bash
# Save baseline from main branch
argus scan all . --format json -o baseline.json

# On PR — only new findings vs baseline
argus scan all . --format json -o current.json --baseline baseline.json

# Diff two reports
argus compare baseline.json current.json --fail-on-new
```

**MCP:** Pass `baseline_json` and `current_json` (AggregatedReport JSON strings) to `compare_scans`.

---

### 4. Secret remediation guidance (#30)

| Item | Location |
|------|----------|
| Remediation catalog | `packages/python/src/argus/remediation/secrets.py` |
| Populated on scan | `packages/python/src/argus/tools/secrets.py` |
| `apply_fix` enrichment | `packages/python/src/argus/tools/fix.py` |

Detectors covered include AWS keys, GitHub tokens, private keys, Stripe, Slack, JWT, NPM, Azure, plus a generic fallback.

Each secret finding now includes `fix_guidance` with numbered rotation/revoke steps and reference links.

---

### 5. DB-focused static rules

| Item | Location |
|------|----------|
| Rule pack | `packages/languages/.../bundled_rules/database.yaml` |

**Rules include:**

| Rule ID | Detects |
|---------|---------|
| `db-connection-string` | Hardcoded `DATABASE_URL`, JDBC, postgres/mysql URLs |
| `db-connection-insecure-ssl` | `sslmode=disable`, `encrypt=false` |
| `db-sqlalchemy-text-fstring` | SQLAlchemy `text(f"...")` |
| `db-django-raw-query` | Django `.raw()` / `.extra()` |
| `db-prisma-raw-query` | Prisma `$queryRaw` |
| `db-migration-grant-all` | `GRANT ALL` in SQL migrations |
| `db-migration-grant-superuser` | `GRANT SUPERUSER` |
| `db-redis-keys-prod` | Redis `KEYS` in production code |
| `db-mongo-where-js` | MongoDB `$where` |
| `db-root-user` | DB connections as root/admin |

Run via: `argus scan code .` (built-in `argus-languages` scanner).

---

## Planned (next milestones)

### CI / DevSecOps

| Feature | Issue | Status |
|---------|-------|--------|
| Official reusable GitHub Action | #37 | Planned |
| PR comment bot with scan summary | #43 | Planned |
| Cloud upload in CI | #34 | Partial (env-based upload exists) |
| Scheduled nightly scans | #35 | Planned |
| Changed-files-only PR scan | #36 | Planned |
| Pre-commit hook | #42 | Planned |
| GitLab CI template | #41 | Planned |

### AI-assisted remediation

| Feature | Issue | Status |
|---------|-------|--------|
| `get_fix_plan` — prioritized fix groups | #28 | Planned |
| `explain_finding` — CWE + checklist | #29 | Planned |
| VS Code "Ask AI to fix" | #31 | Planned |
| Batch `apply_fix` preview | #40 | Planned |

### Database security (extended)

| Feature | Status |
|---------|--------|
| Live read-only DB audit adapter | Planned |
| CIS PostgreSQL/MySQL checks | Planned |
| ORM-specific Semgrep packs | Planned |

### Compliance & reporting

| Feature | Tier | Status |
|---------|------|--------|
| SBOM export (CycloneDX/SPDX) | Pro | Planned |
| PCI/HIPAA rule packs | Pro | Planned |
| Org-wide policy engine (cloud) | Team | Planned |
| Audit log for suppressions | Team | Planned |

---

## Quick reference

```bash
# Full scan with policy + SARIF for GitHub
argus scan all . --format sarif -o argus.sarif --fail-on high

# Baseline diff in CI
argus scan all . --baseline .argus/baseline.json --fail-on-new-only

# Compare two JSON reports
argus compare main-scan.json pr-scan.json --format markdown

# Secret scan with remediation in output
argus scan secrets . --format json

# DB + code rules (no external tools)
argus scan code .
```

---

## Contributing

To add a feature from this roadmap:

1. Open or claim the linked GitHub issue
2. Follow patterns in `docs/architecture.md`
3. Add tests under `packages/python/tests/` or `packages/languages/tests/`
4. Update this document when shipped

See also: [API reference](api-reference.md) · [Getting started](getting-started.md) · [Agent upload](AGENT-UPLOAD.md)
