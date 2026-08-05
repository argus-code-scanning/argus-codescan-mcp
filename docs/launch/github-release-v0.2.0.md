# GitHub Release v0.2.0 — copy/paste

Use at: https://github.com/argus-code-scanning/argus-codescan-mcp/releases/new

- **Tag:** `v0.2.0` (or `v0.2.1` if v0.2.0 tag already exists)
- **Title:** `v0.2.0 — SARIF, policy file, baseline diff, DB rules`

---

## Release notes (paste below)

### Argus v0.2.0 — DevSecOps orchestrator for CLI, MCP, and GitHub

**Argus** is a free, MIT-licensed security scanner that runs **20+ open-source tools** locally (Semgrep, Trivy, Gitleaks, Checkov, tfsec, OWASP ZAP, and more) behind one CLI and one **MCP server** for any MCP-compatible IDE or AI client (Cursor, VS Code, Claude Desktop, JetBrains, etc.).

### What's new

#### SARIF + GitHub Code Scanning (#32, #33)
- `--format sarif` on CLI and MCP
- `.github/workflows/argus-sarif.yml` uploads to GitHub Security tab

```bash
argus scan code . --format sarif -o argus.sarif --fail-on high
```

#### `.argus.yml` policy file
- `fail_on`, `exclude_paths`, suppressions, semgrep config
- Auto-discovered from repo root — see `.argus.yml.example`

#### Baseline diff / PR-only new findings
- `argus compare baseline.json current.json --fail-on-new`
- MCP tool: `compare_scans`
- `--baseline` flag + `fail_on_new_only` in policy

#### Secret remediation (#30)
- Per-detector rotate/revoke guidance (AWS, GitHub, Stripe, private keys, etc.)
- Populated on all secret scan findings

#### DB security static rules
- SQL injection, connection strings, insecure SSL, migration `GRANT ALL`, ORM raw queries
- Run with: `argus scan code .`

#### Other
- Launch kit + README visibility (`docs/launch/`)
- Docker: pin KICS 2.1.20 for reliable multi-arch builds

### Install

| Platform | Command |
|----------|---------|
| Python (full) | `pip install argus-scan` |
| Languages only | `pip install argus-languages` |
| Node/React | `npm install -D argus-codescan` |
| Docker | `docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp` |

### MCP (any MCP-compatible IDE)

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

### Docs
- [Features roadmap](https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/features-roadmap.md)
- [Getting started](https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/getting-started.md)
- [Launch kit / Show HN](https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/launch/show-hn.md)

### Packages in this release
| Package | Version |
|---------|---------|
| `argus-scan` | 0.2.0 |
| `argus-languages` | 0.1.3 |
| `argus-codescan` (npm) | 0.5.0 |

**Full changelog:** PR [#45](https://github.com/argus-code-scanning/argus-codescan-mcp/pull/45), [#46](https://github.com/argus-code-scanning/argus-codescan-mcp/pull/46), [#47](https://github.com/argus-code-scanning/argus-codescan-mcp/pull/47)
