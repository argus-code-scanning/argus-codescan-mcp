# argus-scan (Python)

An **MCP server** that gives AI assistants (Claude, Cursor, etc.) the ability to run comprehensive security scans on your codebase.

## What It Does

Exposes the following **MCP tools** for use by any MCP-compatible AI client:

| Tool | Description | Scanners |
|------|-------------|----------|
| `scan_sast` | Static code analysis | Semgrep, Bandit, ESLint-security |
| `scan_dast` | Dynamic web app scanning | OWASP ZAP, Nikto |
| `scan_sca` | Dependency vulnerability scanning | Trivy, Safety, pip-audit, npm audit |
| `scan_secrets` | Leaked secrets & credentials | Gitleaks, detect-secrets, TruffleHog |
| `scan_iac` | IaC misconfiguration scanning | Checkov, Trivy config, Terrascan |
| `scan_container` | Container image scanning | Trivy |
| `scan_all` | Full scan (all of the above) | All tools |
| `apply_fix` | Preview or apply fix for one finding (only when user asks) | ESLint, Semgrep |
| `get_scan_report` | Reformat scan JSON as Markdown | — |
| `check_tools` | Check tool availability | — |

Scans never modify files. Upload to the cloud dashboard is optional when `ARGUS_API_KEY` is set.

## Installation

### Full suite

```bash
pip install argus-scan
pip install "argus-scan[all-tools]"   # optional: semgrep, bandit, checkov, ansible-lint…
```

Includes **`argus-languages`** automatically (Java, PHP, Flutter, Terraform, Ansible built-in scanning).

### Lightweight code scan only

```bash
pip install argus-languages
argus-languages scan /path/to/project
```

## CLI usage (no MCP)

```bash
argus scan code /path/to/project     # built-in multi-language (argus-languages)
argus scan sast /path/to/project     # + Semgrep, Bandit, ESLint if installed
argus scan sca /path/to/project      # dependencies
argus scan secrets /path/to/project
argus scan iac /path/to/infra
argus scan terraform /path/to/tf
argus scan ansible /path/to/playbooks
argus scan all /path/to/project --fail-on high
argus scan all /path/to/project --upload      # cloud dashboard (ARGUS_API_KEY)
argus scan sast . --no-upload                 # skip cloud upload
argus tools
argus mcp --config                            # MCP JSON with cloud env template
```

### Run the MCP Server

```bash
argus mcp
# or: argus-mcp
```

The server communicates via **stdio** (standard MCP transport).

### Configure in Cursor / Claude Desktop

Add to your MCP configuration (`~/.cursor/mcp.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus-mcp",
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Omit `env` for local-only scans. After each scan, results upload automatically when the API key is set.

Or with `uvx` (no installation required):

```json
{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["--from", "argus-scan", "argus-mcp"]
    }
  }
}
```

## Fix on request

- **Scans** — detect only; no file changes
- **`apply_fix`** — call with `apply=false` for guidance, `apply=true` after user confirms (ESLint / Semgrep autofix)
- **Secrets, SCA, IaC, DAST** — guidance only; use AI or manual edits

VS Code extension: Quick Fix lightbulb on Problems panel findings.

## Cloud dashboard upload

| Env var | Default | Purpose |
|---------|---------|---------|
| `ARGUS_API_KEY` | — | Required to upload (`arg_live_…` from dashboard) |
| `ARGUS_API_URL` | `http://localhost:4000/v1` | API base URL |
| `ARGUS_FAIL_ON` | `high` | Severity for `status: failed` in uploads |

See [docs/AGENT-UPLOAD.md](../../docs/AGENT-UPLOAD.md).

## External Tool Dependencies

The MCP server wraps these external tools. Install the ones you need:

### SAST
```bash
pip install semgrep bandit flake8 flake8-bandit   # Python SAST
npm install -g eslint eslint-plugin-security       # JS/TS SAST
```

### DAST
```bash
docker pull ghcr.io/zaproxy/zaproxy:stable         # OWASP ZAP (recommended)
brew install nikto                                  # Nikto
```

### SCA
```bash
# Trivy (cross-platform)
brew install trivy
# OR
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

pip install safety pip-audit                        # Python SCA
```

### Secret Scanning
```bash
brew install gitleaks trufflehog                   # macOS
pip install detect-secrets                          # cross-platform
```

### IaC
```bash
pip install checkov                                 # Checkov
brew install terrascan                              # Terrascan
```

## Example: Ask Claude to Scan Your Code

Once configured, you can ask:

- *"Scan `/path/to/myproject` for security vulnerabilities"*
- *"Check my Python code for OWASP Top 10 issues using Semgrep"*
- *"Are there any hardcoded secrets in this repository?"*
- *"Fix the SQL injection finding in routes.py line 42"*
- *"Run a full security audit of my codebase"*

## Development

```bash
git clone https://github.com/GabrielOkiri/argus-mcp
cd argus-scan/packages/python
pip install -e ".[dev]"
pytest
```

## License

MIT
