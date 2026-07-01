# Getting Started

## Do I Need an AI Token or Subscription?

**No.** The scanner tools are all open-source and run locally on your machine.

```
┌─────────────────────────────────────────────────────────────┐
│  Mode 1 — Standalone CLI  (no AI, no token, no internet)    │
│                                                             │
│  argus-scan scan sast /my/project                      │
│  argus-scan scan terraform /my/infra                   │
│  argus-scan tools                                      │
│                                                             │
│  Works for anyone who just wants to scan code.              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Mode 2 — AI-assisted via MCP  (optional, needs client)     │
│                                                             │
│  argus-scan mcp   ← starts the server                 │
│  Then Cursor / Claude Desktop drives the scans via chat.    │
│                                                             │
│  Needs: Cursor subscription OR Claude API key               │
│  Does NOT need: any argus-scan token or licence        │
└─────────────────────────────────────────────────────────────┘
```

The only things that need installation are the **open-source scanner tools** themselves
(Semgrep, Trivy, Bandit, etc.) — all free, all local, all CLI tools.

---

## Prerequisites

- Python 3.10+ (for the core server)
- At least one of: pip, uv, npx, or a Go binary

## Step 1 — Install the Server

Pick any install method. They all run the same Python server.

### pip (recommended for developers)
```bash
pip install argus-scan
# With all Python-native scanners:
pip install "argus-scan[all-tools]"
```

### uvx (zero-install — works with uv)
```bash
# No install needed — uvx downloads and runs on demand
uvx argus-scan --help
```

### npx (zero-install — works with Node.js)
```bash
npx -y argus-scan --help
```

### Go binary
```bash
go install github.com/GabrielOkiri/argus-mcp/packages/go/cmd/argus-scan@latest
```

### Shell script (universal)
```bash
curl -sSfL https://raw.githubusercontent.com/GabrielOkiri/argus-mcp/main/packages/shell/install.sh | sh
# Installs to /usr/local/bin/argus-scan
```

### Docker
```bash
docker pull ghcr.io/GabrielOkiri/argus-mcp:latest
docker run --rm -v $(pwd):/workspace ghcr.io/GabrielOkiri/argus-mcp scan-sast /workspace
```

---

## Step 2 — Install Security Tools

Run the check tool to see what's missing:

```bash
argus-scan --check
```

Then install the scanners you want. See [tool-setup.md](./tool-setup.md) for full details.

**Quick minimum install (covers most use cases):**
```bash
pip install semgrep bandit safety pip-audit detect-secrets checkov
brew install trivy gitleaks          # macOS
# or: curl -sfL .../trivy/install.sh | sh   # Linux
```

---

## Step 3 — Configure Your AI Client

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus-scan"
    }
  }
}
```

Or with uvx (no install needed):
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

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus-scan"
    }
  }
}
```

### VS Code

Install the **Argus** extension from the marketplace, then open the Command Palette and run **Security: Check Installed Tools**.

### Any MCP-compatible client

The server uses standard stdio transport. Start it with:
```bash
argus-scan        # or: uvx argus-scan / npx argus-scan
```

---

## Step 4 — Run Your First Scan

### Option A: Standalone CLI (no AI needed)

```bash
# SAST — static code analysis
argus-scan scan sast /path/to/project

# SCA — dependency vulnerabilities
argus-scan scan sca /path/to/project

# Secrets — leaked credentials
argus-scan scan secrets /path/to/repo

# IaC — misconfigurations
argus-scan scan iac /path/to/infra

# Terraform — dedicated Terraform scan
argus-scan scan terraform /path/to/tf

# Ansible — playbook security
argus-scan scan ansible /path/to/playbooks

# DAST — live web app (URL required)
argus-scan scan dast http://localhost:3000

# Container — image scan
argus-scan scan container nginx:latest

# Everything at once
argus-scan scan all /path/to/project

# Check which tools are installed
argus-scan tools
```

**Output formats:**
```bash
argus-scan scan sast /myapp              # Markdown (default)
argus-scan scan sast /myapp -f table     # compact terminal table
argus-scan scan sast /myapp -f json      # raw JSON
argus-scan scan sast /myapp -o report.md # save to file
```

**Only show high+ findings and fail CI if any exist:**
```bash
argus-scan scan sast /myapp --min-severity high --fail-on high
echo $?   # 1 if high/critical findings found, 0 otherwise
```

### Option B: AI-assisted via MCP

Once your AI client is configured, try these prompts:

```
Scan /path/to/my/project for security vulnerabilities
```

```
Are there any hardcoded secrets in this repository?
```

```
Check my Python dependencies for known CVEs
```

```
Scan my Kubernetes manifests for security misconfigurations
```

```
Run a full security audit of my codebase and give me a prioritised fix list
```

---

## Minimal Working Example (Python SDK)

```python
import asyncio
from argus.tools.sast import run_semgrep
from argus.tools.sca import run_trivy_fs

async def main():
    sast = await run_semgrep("/path/to/project")
    sca = await run_trivy_fs("/path/to/project")

    for result in [sast, sca]:
        print(f"\n{result.tool}: {len(result.findings)} findings")
        for f in result.findings[:5]:
            print(f"  [{f.severity.value}] {f.title} — {f.file}:{f.line}")

asyncio.run(main())
```

---

## Troubleshooting

**Server doesn't start**
```bash
argus-scan --check   # check Python is reachable
python3 -m argus.server  # run directly to see errors
```

**Tool not found**
```bash
# The check_tools MCP tool shows install instructions
# Or run:
argus-scan --check
```

**Semgrep times out**
```bash
# Reduce scope with a specific config
{ "semgrep_config": "p/python", "timeout": 60 }
```

**OWASP ZAP not available**
```bash
# Install Docker and pull the ZAP image:
docker pull ghcr.io/zaproxy/zaproxy:stable
```
