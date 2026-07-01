# argus-scan (Docker)

A Docker image bundling the Python MCP server **and all supported scanners** — no local installs needed beyond Docker.

## Included Tools

| Tool | Version |
|------|---------|
| Semgrep | latest |
| Bandit | latest |
| ESLint + eslint-plugin-security | latest |
| Trivy | latest |
| Safety | latest |
| pip-audit | latest |
| detect-secrets | latest |
| Checkov | latest |
| Gitleaks | latest |
| TruffleHog | latest |
| Terrascan | latest |
| Nikto | distro package |

> OWASP ZAP is **not** bundled (it needs its own container). Use `docker run ghcr.io/zaproxy/zaproxy:stable` separately.

## Pull

```bash
docker pull ghcr.io/GabrielOkiri/argus-mcp:latest
```

## Use as MCP Server

Add to your MCP client config (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${workspaceFolder}:/workspace",
        "ghcr.io/GabrielOkiri/argus-mcp:latest"
      ]
    }
  }
}
```

## Build Locally

From the repo root:

```bash
docker build -f packages/docker/Dockerfile -t argus-scan .
```

## Run Directly

```bash
# Full scan of current directory
docker run --rm -v $(pwd):/workspace ghcr.io/GabrielOkiri/argus-mcp \
  python -m argus.tools.sast --target /workspace
```
