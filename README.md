# Argus

> *In Greek mythology, Argus Panoptes was the hundred-eyed giant — an all-seeing guardian who never slept.*

**One open-source scanner. Many eyes. SAST, SCA, secrets, IaC, Terraform, Ansible — CLI, MCP, and GitHub SARIF.**

Argus orchestrates **20+ industry-standard tools** (Semgrep, Trivy, Gitleaks, tfsec, Checkov, OWASP ZAP, and more) behind a single command and an **MCP server** for any MCP-compatible IDE or AI client. Runs locally. **No Argus subscription.** MIT licensed.

[![Python CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-python.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-python.yml)
[![npm CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-npm.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-npm.yml)
[![Go CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-go.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Install:** `pip install argus-scan` · `npm install -D argus-codescan` · [Docker](packages/docker/README.md) · [Launch kit](docs/launch/show-hn.md)

---

## Why Argus?

| | Run scanners yourself | Argus |
|---|----------------------|--------|
| **Setup** | Install & configure each tool separately | One CLI / MCP config |
| **Output** | Different JSON/text per tool | Unified report + SARIF |
| **CI** | Wire scripts yourself | `--format sarif`, `.argus.yml`, baseline diff |
| **AI (MCP IDE)** | Manual copy-paste | MCP tools: `scan_all`, `compare_scans`, `apply_fix` |
| **Cost** | Free (DIY labor) | Free (MIT) — AI client optional |
| **Fixes** | You decide | Scan never auto-fixes; fix only when you ask |

**Good for:** solo devs, OSS maintainers, teams wanting DevSecOps without a proprietary scanner SaaS.

**Not a replacement for:** managed AppSec platforms with centralized policy, SOC, or compliance sign-off — Argus is a **local orchestrator** you own.

---

## Two ways to use Argus

### 1 — Standalone CLI (no AI needed)

```bash
argus scan sast /my/project
argus scan terraform /my/infra
argus scan all /my/project --fail-on high
argus scan code /my/project --format sarif -o argus.sarif
argus compare baseline.json current.json --fail-on-new
argus tools
```

Works for anyone. Just install Argus and the open-source scanner tools.

### 2 — MCP server (AI-assisted, optional)

```bash
argus mcp    # starts the MCP server
```

Connect Cursor, VS Code, Claude Desktop, JetBrains, Windsurf, or any MCP-compatible IDE and drive scans through natural language. The AI subscription is for the AI client — Argus itself is always free.

---

## What Argus Scans

| Category | Tools |
|----------|-------|
| **SAST** | Semgrep · Bandit · ESLint-security · flake8-bandit |
| **DAST** | OWASP ZAP · Nikto |
| **SCA** | Trivy · Safety · pip-audit · npm audit |
| **Secrets** | Gitleaks · detect-secrets · TruffleHog |
| **IaC** | Checkov · Trivy config · Terrascan · KICS |
| **Terraform** | tfsec · tflint · terraform validate · KICS · Checkov |
| **Ansible** | ansible-lint · KICS · Checkov |
| **Container** | Trivy image scan |

## MCP Tools (for AI clients)

| Tool | What It Does |
|------|-------------|
| `scan_sast` | Static code analysis — all languages |
| `scan_dast` | Dynamic scan of a running web app |
| `scan_sca` | Vulnerable dependency detection |
| `scan_secrets` | Leaked API keys, tokens, passwords |
| `scan_iac` | Terraform, K8s, Dockerfile, Helm, Ansible misconfigs |
| `scan_terraform` | Deep Terraform scan (tfsec, tflint, validate, KICS) |
| `scan_ansible` | Ansible playbook & role security scan |
| `scan_container` | Container image CVE scanning |
| `scan_all` | Everything, in parallel |
| `apply_fix` | Preview or apply a fix for one finding (user must ask — scans never auto-fix) |
| `compare_scans` | Diff baseline vs current scan JSON (new/fixed findings) |
| `get_scan_report` | Reformat a previous scan JSON as Markdown or SARIF |
| `check_tools` | List which scanners are installed |

Scans are **read-only**. Fixes run only when you ask — via `apply_fix`, VS Code Quick Fix, or your AI editing code from `fix_guidance`.

---

## Fix on request

Argus **never modifies your code during a scan**. After results come back:

| How | AI token needed? |
|-----|:----------------:|
| **VS Code Quick Fix** (lightbulb → Show fix guidance / Apply automated fix) | No |
| **MCP `apply_fix`** with `apply=true` (ESLint / Semgrep autofix only) | Only if AI calls it for you |
| **AI edits code** from finding guidance (secrets, CVEs, IaC, OWASP, etc.) | Yes (for the AI client) |

```bash
# CLI and MCP scans — detect only
argus scan all /path/to/project

# MCP: user asks AI to fix a specific finding
# → apply_fix { target, file, tool, apply: true }
```

Details: [API Reference — apply_fix](docs/api-reference.md#apply_fix)

---

## SARIF, policy & baseline diff

Ship security findings to GitHub Code Scanning, enforce repo policy, and fail CI only on **new** findings.

### SARIF export (GitHub Security tab)

```bash
# Export SARIF for GitHub Code Scanning
argus scan code . --format sarif -o argus.sarif --fail-on high

# MCP: scan_sast / scan_all with format: "sarif"
```

Upload in GitHub Actions (see `.github/workflows/argus-sarif.yml`):

```yaml
- run: pip install argus-scan && argus scan code . --format sarif -o argus.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
    category: argus
```

### `.argus.yml` policy file

Copy [`.argus.yml.example`](.argus.yml.example) to `.argus.yml` in your repo root:

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

Argus auto-discovers `.argus.yml` when scanning. Override with `--policy path/to/.argus.yml`.

### Baseline diff (PR-only new findings)

```bash
# Save baseline from main
argus scan all . --format json -o baseline.json

# On PR — compare against baseline
argus scan all . --baseline baseline.json --format json -o current.json
argus compare baseline.json current.json --fail-on-new

# Or set in .argus.yml:
# baseline: .argus/baseline.json
# fail_on_new_only: true
```

### Secret remediation guidance

Secret findings include step-by-step rotate/revoke guidance (AWS, GitHub tokens, private keys, Stripe, etc.):

```bash
argus scan secrets . --format json   # fix_guidance on each finding
# MCP apply_fix for secrets returns remediation steps (no auto-fix)
```

### Database security rules

Built-in static rules for SQL injection, connection strings, migration GRANTs, ORM raw queries:

```bash
argus scan code .    # includes database.yaml rules via argus-languages
```

Full docs: [docs/features-roadmap.md](docs/features-roadmap.md) · [API reference](docs/api-reference.md)

---

## Cloud dashboard upload (optional)

Send scan results to the Argus cloud dashboard when `ARGUS_API_KEY` is set. Local scans still work without any key.

```bash
export ARGUS_API_URL=http://localhost:4000/v1   # default
export ARGUS_API_KEY=arg_live_PASTE_YOUR_KEY

argus scan all /path/to/project                 # uploads automatically
argus scan sast . --upload --fail-on high       # force upload
argus scan secrets . --no-upload                # skip upload
```

**MCP** — add env to your IDE's MCP config (e.g. Cursor `~/.cursor/mcp.json`, VS Code MCP settings, Claude Desktop config):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"],
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Print the same template: `argus mcp --config`

After each MCP scan or CLI scan, results upload to `{ARGUS_API_URL}/scans` with repo/branch/commit from git. Full setup: [docs/AGENT-UPLOAD.md](docs/AGENT-UPLOAD.md)

---

## Install

Pick the package that matches your project:

| Your project | Install | Scan command |
|--------------|---------|--------------|
| **React / Next.js / Node** | `npm install -D argus-codescan` | `npx argus-codescan scan all .` |
| **Java, PHP, Flutter, Terraform, Ansible** | `pip install argus-languages` | `argus-languages scan /path/to/project` |
| **Full suite (MCP, DAST, IaC tools)** | `pip install argus-scan` | `argus scan all /path/to/project` |

### React / Node (npm) — no Python required

```bash
npm install -D argus-codescan

npx argus-codescan scan sca .       # dependencies (npm audit)
npx argus-codescan scan sast .      # source code (JS/TS)
npx argus-codescan scan secrets .   # API keys, tokens
npx argus-codescan scan all .       # everything

# CSV report written automatically (or set path with --output)
npx argus-codescan scan all . --output ./reports/security.csv
```

Add to `package.json`:

```json
{
  "scripts": {
    "security:scan": "argus-codescan scan sca . --output ./reports/deps.csv",
    "security:code": "argus-codescan scan sast . --output ./reports/code.csv",
    "security:secrets": "argus-codescan scan secrets . --output ./reports/secrets.csv",
    "security:all": "argus-codescan scan all . --output ./reports/full.csv"
  }
}
```

### Java, PHP, Flutter, IaC (pip — lightweight)

```bash
pip install argus-languages

# Any supported language / IaC in one command
argus-languages scan /path/to/project

# Examples
argus-languages scan ./my-java-app
argus-languages scan ./terraform
argus-languages scan ./flutter-app
```

### Full Argus CLI + MCP (pip)

```bash
pip install argus-scan
# With all Python-native scanners:
pip install "argus-scan[all-tools]"

argus scan code /path/to/project    # built-in multi-language (uses argus-languages)
argus scan sast /path/to/project    # + Semgrep, Bandit, ESLint if installed
argus scan terraform /path/to/infra
argus scan ansible /path/to/playbooks
argus scan all /path/to/project --fail-on high
argus scan all /path/to/project --upload          # cloud dashboard (needs ARGUS_API_KEY)
argus scan all . --format sarif -o argus.sarif    # GitHub Code Scanning export
argus compare baseline.json current.json          # diff two scan JSON files
argus tools                         # show installed scanners
argus mcp                           # start MCP server for any MCP-compatible IDE
argus mcp --config                  # print MCP config with cloud env vars
```

### Zero-install

```bash
uvx argus-scan       # full Python CLI via uv
npx argus-codescan   # Node/React via npm
```

### Go (single binary)

```bash
go install github.com/OkiriGabriel/argus-codescan-mcp/packages/go/cmd/argus@latest
```

### Shell script

```bash
curl -sSfL https://raw.githubusercontent.com/OkiriGabriel/argus-codescan-mcp/main/packages/shell/install.sh | sh
```

### Docker (all scanners bundled)

```bash
docker pull ghcr.io/okirigabriel/argus-codescan-mcp:latest

# MCP server (add to ~/.cursor/mcp.json — see packages/docker/README.md)
docker run --rm -i -v "$(pwd):/workspace" ghcr.io/okirigabriel/argus-codescan-mcp

# One-shot CLI scan
docker run --rm -v "$(pwd):/workspace" ghcr.io/okirigabriel/argus-codescan-mcp \
  scan all /workspace
```

Full Docker guide: [packages/docker/README.md](packages/docker/README.md)

### VS Code Extension

Install **Argus Security Scanner** from the VS Code Marketplace.

---

## Quick Start

### React / Next.js

```bash
npm install -D argus-codescan
npm run security:all   # after adding scripts — see Install section above
```

### Flutter / Java / PHP / Terraform

```bash
pip install argus-languages
argus-languages scan /path/to/project
```

### Full CLI (all scan types)

```bash
pip install "argus-scan[all-tools]"
argus tools
argus scan code /path/to/project
argus scan terraform /path/to/infra
argus scan all /path/to/project --format table
argus scan all /path/to/project --fail-on high
```

### MCP (any MCP-compatible IDE)

Add to your MCP client config (e.g. Cursor `~/.cursor/mcp.json`, VS Code MCP settings, Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"],
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Omit the `env` block if you only want local scans (no cloud upload). Or zero-install with `uvx`:

```json
{
  "mcpServers": {
    "argus": { "command": "uvx", "args": ["argus-scan", "mcp"] }
  }
}
```

Then ask your AI:
```
Scan /path/to/myproject for security vulnerabilities
Are there any hardcoded secrets in this repo?
Fix the high-severity finding in src/api.js line 42
Run a full security audit and give me a prioritised fix list
```

---

## Install Scanners

Run `argus tools` to see what's installed. Quick install for common tools:

```bash
# macOS
brew install semgrep trivy gitleaks trufflehog tfsec tflint kics
pip install bandit safety pip-audit detect-secrets checkov ansible-lint
docker pull ghcr.io/zaproxy/zaproxy:stable   # OWASP ZAP

# Linux
pip install "argus-scan[all-tools]"
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

Full guide: [docs/tool-setup.md](docs/tool-setup.md)

---

## Do I Need a Token or Subscription?

**No Argus subscription** for local scanning. Every scanner runs on your machine:

| Layer | Cost | Requires |
|-------|------|---------|
| Argus CLI & MCP | Free | Python 3.10+ |
| Semgrep, Trivy, Bandit, tfsec… | Free | Local install |
| Cloud dashboard upload | Optional | `ARGUS_API_KEY` from your dashboard |
| AI client (Cursor, Claude) | Subscription | Only for chat-driven scans and fixes |

The AI subscription is for the **AI client**, not for Argus. Cloud upload uses your **Argus API key** (`arg_live_…`), not your Cursor/Claude token.

---

## Repository Structure

```
argus-codescan-mcp/
├── packages/
│   ├── python/          pip install argus-scan
│   │   └── src/argus/
│   │       ├── cli.py             Standalone CLI
│   │       ├── server.py          MCP server
│   │       ├── cloud_upload.py    Optional dashboard upload
│   │       └── tools/             SAST, DAST, SCA, secrets, IaC, …
│   ├── languages/       pip install argus-languages  ← Java, PHP, Terraform, Ansible, all code
│   │   └── src/argus_languages/
│   │       └── bundled_rules/     YAML rules shared across Python (and future Go client)
│   ├── npm/             npx argus-codescan  (Node.js / JS-TS only)
│   ├── go/              go install .../argus@latest
│   ├── shell/           curl | sh installer
│   └── docker/          ghcr.io/okiriGabriel/argus-codescan-mcp
├── extensions/
│   └── vscode/          Argus Security Scanner VS Code extension
├── docs/
│   ├── getting-started.md
│   ├── architecture.md
│   ├── api-reference.md
│   ├── AGENT-UPLOAD.md
│   └── tool-setup.md
└── .github/
    ├── workflows/        CI for Python, npm, Go, VS Code, Docker
    └── ISSUE_TEMPLATE/
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Getting Started](docs/getting-started.md) | Install, configure, first scan |
| [Architecture](docs/architecture.md) | How Argus works under the hood |
| [API Reference](docs/api-reference.md) | All MCP tools, parameters, schemas |
| [Agent Upload](docs/AGENT-UPLOAD.md) | Cloud dashboard upload & API keys |
| [Tool Setup](docs/tool-setup.md) | Install every scanner on every platform |
| [Contributing](CONTRIBUTING.md) | Add scanners, clients, and fixes |
| [Security Policy](SECURITY.md) | Report vulnerabilities |

---

## Contributing

All contributions welcome — new scanners, new language clients, bug fixes, docs.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE)
