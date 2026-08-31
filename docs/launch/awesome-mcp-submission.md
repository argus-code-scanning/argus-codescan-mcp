# Awesome MCP Servers — submission

Use this when opening a PR to [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) or similar lists.

---

## PR title

```
Add Argus — open-source security scanner (SAST, SCA, secrets, IaC)
```

---

## Entry (markdown — adjust category to match the list's sections)

Pick the section that fits best — **Developer Tools** is recommended (Security TOC link may not have a dedicated section in current README):

```markdown
- [argus-code-scanning/argus-codescan-mcp](https://github.com/argus-code-scanning/argus-codescan-mcp) 🐍 📇 🏠 🍎 🪟 🐧 - Open-source multi-scanner security tool (SAST, DAST, SCA, secrets, IaC, Terraform, Ansible). Single MCP server orchestrating Semgrep, Trivy, Gitleaks, Checkov, tfsec, and 15+ tools. SARIF export, `.argus.yml` policy, baseline diff, fix-on-request. MIT. `pip install argus-scan`
```

**Where to add:** Under `### 💻 Developer Tools` in [README.md](https://github.com/punkpeye/awesome-mcp-servers/blob/main/README.md) (alphabetically near other `a*` entries, e.g. after `aradar46/reuse-before-generate`).

**Shorter variant:**

```markdown
- [Argus](https://github.com/argus-code-scanning/argus-codescan-mcp) - Local DevSecOps scanner via MCP: SAST, SCA, secrets, IaC. Normalized reports, SARIF, fix-on-request. MIT.
```

---

## MCP config snippet (if the list asks for examples)

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

With uvx (no install):

```json
{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["argus-scan", "mcp"]
    }
  }
}
```

---

## PR description template

```markdown
## Add Argus

**Repository:** https://github.com/argus-code-scanning/argus-codescan-mcp

**Category:** Security / Developer Tools

Argus is an MCP server that exposes security scanning as tools (`scan_sast`, `scan_sca`, `scan_secrets`, `scan_iac`, `scan_all`, `compare_scans`, `apply_fix`, etc.). It wraps open-source scanners locally — no proprietary cloud required for scanning.

- MIT license
- Active development (CLI + VS Code extension + Docker image)
- PyPI: `argus-scan` | npm: `argus-codescan`

Happy to adjust wording or category per maintainer preference.
```

---

## Other lists to submit (same entry, tweak category)

| List | URL |
|------|-----|
| Awesome MCP Servers | https://github.com/punkpeye/awesome-mcp-servers |
| Awesome Security | https://github.com/sbilly/awesome-security |
| Awesome DevSecOps | https://github.com/TrendMicro/awesome-devsecops |
| Cursor MCP (community docs) | Search "cursor mcp servers" for current community repos |

---

## Checklist before submitting

- [ ] README has clear one-liner and install instructions
- [ ] GitHub repo has **Topics** set: `mcp`, `security`, `sast`, `devsecops`
- [ ] Latest release tagged on GitHub (e.g. `v0.2.0`)
- [ ] PyPI/npm published (optional but helps reviewers)
