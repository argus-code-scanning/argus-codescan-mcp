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
| `check_tools` | Check tool availability | — |

## Installation

```bash
pip install argus-scan
```

Install with all Python-native security tools:

```bash
pip install "argus-scan[all-tools]"
```

## Usage

### Run the MCP Server

```bash
argus-scan
```

The server communicates via **stdio** (standard MCP transport).

### Configure in Cursor / Claude Desktop

Add to your MCP configuration (`~/.cursor/mcp.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus-scan"
    }
  }
}
```

Or with `uvx` (no installation required):

```json
{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["argus-scan"]
    }
  }
}
```

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
- *"Scan my Kubernetes manifests for misconfigurations"*
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
