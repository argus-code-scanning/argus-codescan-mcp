# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in `argus-scan` itself (not in one of the third-party tools it wraps), please report it via one of these channels:

1. **GitHub Private Vulnerability Reporting** — use the "Report a vulnerability" button on the Security tab of this repository.
2. **Email** — send details to `security@gabrielokiri.dev` with the subject `[argus-mcp] Security Vulnerability`.

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigation

You will receive an acknowledgement within **48 hours** and a full response within **7 days**.

## Scope

Issues in scope:
- The Python MCP server (`packages/python/`)
- The npm wrapper (`packages/npm/`)
- The Go CLI (`packages/go/`)
- The VS Code extension (`extensions/vscode/`)
- The shell script installer (`packages/shell/`)

Issues out of scope (report to the upstream project):
- Vulnerabilities in Semgrep, Bandit, Trivy, OWASP ZAP, Gitleaks, etc.
- Vulnerabilities in MCP itself (report to Anthropic)

## Responsible Disclosure

We kindly ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Not access or modify other users' data during testing
- Not perform denial-of-service attacks

We will publicly acknowledge your contribution in the release notes (unless you prefer to remain anonymous).
