# Argus Security Scanner — VS Code Extension

Comprehensive security scanning directly in VS Code, powered by OWASP ZAP, Semgrep, Trivy, Bandit, Gitleaks, Checkov, and more.

## Features

- **SAST** — Static code analysis (Semgrep, Bandit, ESLint security)
- **DAST** — Dynamic web app scanning (OWASP ZAP, Nikto)
- **SCA** — Dependency vulnerability scanning (Trivy, Safety, pip-audit, npm audit)
- **Secret Scanning** — Leaked credentials (Gitleaks, detect-secrets, TruffleHog)
- **IaC Scanning** — Terraform, Kubernetes, Dockerfile misconfigs (Checkov, Trivy)
- **Container Scanning** — Image CVE scanning (Trivy)
- **Problems Panel** — Findings appear as VS Code diagnostics
- **Fix on request** — Quick Fix actions to view guidance or apply an automated fix (never during scan)
- **Scan Dashboard** — Interactive webview with full report
- **Scan on Save** — Optional auto-scan when files change

## Requirements

Install the Python server:

```bash
pip install argus-scan
```

Or use `uvx` (no install needed) — configure in settings.

## Commands

Open the Command Palette (`⇧⌘P`) and search for **Security**:

| Command | Description |
|---------|-------------|
| Security: Run SAST Scan | Static code analysis |
| Security: Run SCA Scan | Dependency scanning |
| Security: Scan for Secrets | Credential detection |
| Security: Run IaC Scan | IaC misconfiguration |
| Security: Run DAST Scan | Web app dynamic scan |
| Security: Scan Container Image | Image CVE scan |
| Security: Run Full Security Scan | All of the above |
| Security: Check Installed Tools | Tool availability |
| Security: Open Scan Dashboard | Open report panel |
| Security: Clear Diagnostics | Clear Problems panel |
| *(Quick Fix on finding)* | Show fix guidance or apply automated fix |

Scans **never modify your code**. To fix a finding, click the lightbulb on a diagnostic and choose **Show fix guidance** or **Apply automated fix** (ESLint/Semgrep only).

You can also **right-click** any file or folder in the Explorer to run a security scan.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `argus-scan.mcpServerCommand` | _(auto)_ | Custom server start command |
| `argus-scan.semgrepConfig` | `auto` | Semgrep ruleset config |
| `argus-scan.scanOnSave` | `false` | Auto-scan on file save |
| `argus-scan.showInlineDecorations` | `true` | Inline finding hints |
| `argus-scan.minSeverity` | `low` | Minimum severity to show |
| `argus-scan.scanTimeout` | `300` | Scan timeout in seconds |

## Also Available As MCP Server

This extension works with the same MCP server that powers Cursor and Claude Desktop integrations. See the [main README](../../README.md) for the full picture.
