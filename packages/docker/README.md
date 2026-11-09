# Argus (Docker)

A Docker image bundling the Argus MCP server **and all supported scanners** — no local installs needed beyond Docker.

## Included Tools

| Tool | Purpose |
|------|---------|
| Semgrep | SAST (all languages) |
| Bandit | SAST (Python) |
| ESLint + eslint-plugin-security | SAST (JS/TS) |
| flake8-bandit | SAST (Python) |
| Trivy | SCA + container + IaC |
| Safety / pip-audit | Python dependency audit |
| detect-secrets | Secret scanning |
| Gitleaks / TruffleHog | Secret scanning |
| Checkov | IaC misconfigurations |
| Terrascan | IaC misconfigurations |
| tfsec / tflint / terraform | Terraform security |
| KICS | IaC (Terraform, K8s, Ansible, …) |
| ansible-lint | Ansible playbook linting |
| Nikto | Web server scanner |

> OWASP ZAP is **not** bundled (it needs its own container). See [DAST (OWASP ZAP) inside the container](#dast-owasp-zap-inside-the-container).

## Prerequisites

You need a container engine. **Docker Desktop is not required.**

| Setup | Install | Start |
|-------|---------|-------|
| **Colima** (recommended on Mac) | `brew install colima docker docker-compose` | `colima start` |
| **Podman** | `brew install podman podman-compose` | `podman machine init && podman machine start` |
| **OrbStack** | [orbstack.dev](https://orbstack.dev) | starts automatically |

### Mac without Docker Desktop (Apple Silicon)

Colima is a lightweight, free Docker-compatible runtime for M-series Macs:

```bash
# One-time setup
brew install colima docker docker-compose
colima start --cpu 4 --memory 8

# Build native arm64 image (Colima uses aarch64 by default on Apple Silicon)
docker build -f packages/docker/Dockerfile -t argus-scan .

# Confirm architecture
docker image inspect argus-scan --format '{{.Architecture}}'
# → arm64

# Test
docker run --rm argus-scan tools
```

If `docker` says it cannot connect to the socket, the daemon is not running — start Colima first:

```bash
colima status    # check
colima start     # start if stopped
```

**Podman alternative** — same image, swap `docker` → `podman`:

```bash
podman machine init
podman machine start
podman build -f packages/docker/Dockerfile -t argus-scan .
podman run --rm argus-scan tools
```

For Cursor MCP with Podman, use `"command": "podman"` in `~/.cursor/mcp.json` instead of `"docker"`.

## Pull

```bash
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:latest
```

## Build Locally

**Important:** the build context must be the **repo root** (the Dockerfile copies `packages/python/` and `packages/languages/`).

### Option A — build script (works from anywhere)

```bash
./packages/docker/build.sh
```

### Option B — from repo root

```bash
cd /path/to/argus-codescan-mcp   # repo root, NOT packages/docker
docker build --platform linux/arm64 -f packages/docker/Dockerfile -t argus-scan .
```

### Option C — if you are already in `packages/docker/`

```bash
docker build --platform linux/arm64 -f Dockerfile -t argus-scan ../..
```

> If you see `lstat .../packages/docker/packages: no such file or directory`, you ran the repo-root command from the wrong directory. Use option A or C above.

Or with Compose (from repo root):

```bash
docker compose -f packages/docker/docker-compose.yml build
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
        "ghcr.io/argus-code-scanning/argus-codescan-mcp:latest"
      ]
    }
  }
}
```

No args needed — the container starts the MCP server over stdio by default.

## Run CLI Scans

The same image works as a one-shot scanner. Mount your project at `/workspace` and pass `argus` subcommands:

```bash
# List installed scanners
docker run --rm ghcr.io/argus-code-scanning/argus-codescan-mcp tools

# Full security audit
docker run --rm -v "$(pwd):/workspace" ghcr.io/argus-code-scanning/argus-codescan-mcp \
  scan all /workspace

# SAST only
docker run --rm -v "$(pwd):/workspace" ghcr.io/argus-code-scanning/argus-codescan-mcp \
  scan sast /workspace

# Terraform / IaC
docker run --rm -v "$(pwd):/workspace" ghcr.io/argus-code-scanning/argus-codescan-mcp \
  scan terraform /workspace

# Fail CI on high+ findings
docker run --rm -v "$(pwd):/workspace" ghcr.io/argus-code-scanning/argus-codescan-mcp \
  scan all /workspace --fail-on high
```

With Compose (from repo root):

```bash
docker compose -f packages/docker/docker-compose.yml run --rm argus tools
docker compose -f packages/docker/docker-compose.yml run --rm argus scan all /workspace
```

## DAST (OWASP ZAP) inside the container

On the host, `argus scan dast` starts ZAP with `docker run ghcr.io/zaproxy/zaproxy:stable`. Inside the Argus container that usually fails: the image has no `docker` CLI and no access to a Docker daemon. When Argus detects it is running in a container (`/.dockerenv` or `/run/.containerenv`), it reports this instead of the generic install instructions.

Nikto is bundled and works inside the container. For ZAP, pick one:

1. **Run DAST from the host (recommended).** Install Argus locally (`pip install argus-scan`) and run `argus scan dast <url>`.
2. **Run ZAP as its own container** and read its report directly:

   ```bash
   docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000
   ```

3. **Mount the host Docker socket** and add the docker CLI to a derived image:

   ```bash
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock my-argus-with-docker-cli \
     scan dast http://host.docker.internal:3000
   ```

   > **Security:** mounting `docker.sock` gives the container root-equivalent control of the host. Only do this on trusted machines and never in shared CI runners.

**Target URLs:** inside a container, `localhost` is the container itself, not your machine. Use `http://host.docker.internal:<port>` (Docker Desktop, OrbStack, Colima) or add `--add-host=host.docker.internal:host-gateway` on Linux.

## CI Example

```yaml
- name: Security scan
  run: |
    docker run --rm \
      -v "${{ github.workspace }}:/workspace" \
      ghcr.io/argus-code-scanning/argus-codescan-mcp:latest \
      scan all /workspace --fail-on high --format json --output /workspace/argus-report.json
```

## Publish

Images are built and pushed to GitHub Container Registry on push to `main` or version tags (`v*`). See `.github/workflows/docker.yml`.

Make the package public under **GitHub → Packages → argus-codescan-mcp → Package settings** so anyone can pull without auth.
