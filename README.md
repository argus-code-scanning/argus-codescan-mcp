# Argus

> *In Greek mythology, Argus Panoptes was the hundred-eyed giant — an all-seeing guardian who never slept.*

**Argus is an open-source security scanner with many eyes.**

It brings together 20+ industry-standard scanning tools — Semgrep, Trivy, OWASP ZAP, Bandit, Gitleaks, tfsec, ansible-lint, KICS, Checkov, TruffleHog, and more — behind a single CLI and MCP server. Run SAST, DAST, SCA, secret scanning, IaC, Terraform, and Ansible security audits with one command. No AI subscription required.

[![Python CI](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-python.yml/badge.svg)](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-python.yml)
[![npm CI](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-npm.yml/badge.svg)](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-npm.yml)
[![Go CI](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-go.yml/badge.svg)](https://github.com/GabrielOkiri/argus-codescan-mcp/actions/workflows/ci-go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Two ways to use Argus

### 1 — Standalone CLI (no AI needed)

```bash
argus scan sast /my/project
argus scan terraform /my/infra
argus scan all /my/project --fail-on high
argus tools
```

Works for anyone. Just install Argus and the open-source scanner tools.

### 2 — MCP server (AI-assisted, optional)

```bash
argus mcp    # starts the MCP server
```

Connect Cursor, Claude Desktop, or any MCP-compatible AI assistant and drive scans through natural language. The AI subscription is for the AI client — Argus itself is always free.

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
| `check_tools` | List which scanners are installed |

---

## Install

### Python (pip)

```bash
pip install argus-scan
# With all Python-native scanners:
pip install "argus-scan[all-tools]"
```

### Zero-install

```bash
uvx argus-scan       # via uv
npx argus-scan       # via npm
```

### Go (single binary)

```bash
go install github.com/GabrielOkiri/argus-mcp/packages/go/cmd/argus-scan@latest
```

### Shell script

```bash
curl -sSfL https://raw.githubusercontent.com/GabrielOkiri/argus-mcp/main/packages/shell/install.sh | sh
```

### Docker (all scanners bundled)

```bash
docker pull ghcr.io/GabrielOkiri/argus-mcp:latest
```

### VS Code Extension

Install **Argus Security Scanner** from the VS Code Marketplace.

---

## Quick Start

### CLI

```bash
# Install Argus
pip install "argus-scan[all-tools]"

# Check which scanners are ready
argus tools

# Scan a project
argus scan sast /path/to/project
argus scan terraform /path/to/infra
argus scan all /path/to/project --format table

# CI/CD — fail the build on high+ findings
argus scan all /path/to/project --fail-on high
```

### MCP (Cursor / Claude Desktop)

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus": { "command": "argus", "args": ["mcp"] }
  }
}
```

Or zero-install with `uvx`:

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
Scan my Kubernetes manifests for misconfigurations
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

**No.** Every scanner Argus uses is open-source and runs locally:

| Layer | Cost | Requires |
|-------|------|---------|
| Argus CLI | Free | Python 3.10+ |
| Semgrep, Trivy, Bandit, tfsec… | Free | Local install |
| Argus MCP server | Free | Python 3.10+ |
| AI client (Cursor, Claude) | Subscription needed | Only if you want AI-driven scanning |

The AI subscription is for the **AI client**, not for Argus.

---

## Repository Structure

```
argus-scan/
├── packages/
│   ├── python/          pip install argus-scan
│   │   └── src/argus/
│   │       ├── cli.py             Standalone CLI
│   │       ├── server.py          MCP server
│   │       ├── models.py          Shared data models
│   │       ├── utils.py           Subprocess helpers
│   │       └── tools/
│   │           ├── sast.py        Semgrep, Bandit, ESLint
│   │           ├── dast.py        OWASP ZAP, Nikto
│   │           ├── sca.py         Trivy, Safety, pip-audit, npm audit
│   │           ├── secrets.py     Gitleaks, detect-secrets, TruffleHog
│   │           ├── iac.py         Checkov, Trivy config, Terrascan
│   │           ├── terraform.py   tfsec, tflint, terraform validate, KICS
│   │           └── ansible.py     ansible-lint, KICS, Checkov
│   ├── npm/             npm install argus-scan
│   ├── go/              go install .../argus-scan@latest
│   ├── shell/           curl | sh installer
│   └── docker/          ghcr.io/GabrielOkiri/argus-mcp
├── extensions/
│   └── vscode/          Argus Security Scanner VS Code extension
├── docs/
│   ├── getting-started.md
│   ├── architecture.md
│   ├── api-reference.md
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
| [Tool Setup](docs/tool-setup.md) | Install every scanner on every platform |
| [Contributing](CONTRIBUTING.md) | Add scanners, clients, and fixes |
| [Security Policy](SECURITY.md) | Report vulnerabilities |

---

## Contributing

All contributions welcome — new scanners, new language clients, bug fixes, docs.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE)
