# Architecture

## Overview

`argus-scan` is a **Model Context Protocol (MCP) server** that exposes security scanning capabilities as structured tools an AI assistant can call. It wraps industry-standard open-source scanners behind a single, normalised interface.

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Client (AI)                       │
│          Cursor / Claude Desktop / custom agent          │
└────────────────────────┬────────────────────────────────┘
                         │  JSON-RPC 2.0 over stdio
                         ▼
┌─────────────────────────────────────────────────────────┐
│               argus-scan Server                     │
│                  (Python core)                           │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │  scan_   │ │  scan_   │ │  scan_   │ │  scan_    │  │
│  │  sast    │ │  dast    │ │  sca     │ │  secrets  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘  │
│       │            │            │              │         │
│  ┌────▼─────┐ ┌────▼─────┐ ┌───▼──────┐ ┌────▼─────┐  │
│  │ Semgrep  │ │ OWASP ZAP│ │  Trivy   │ │Gitleaks  │  │
│  │ Bandit   │ │ Nikto    │ │  Safety  │ │detect-   │  │
│  │ ESLint   │ │          │ │ pip-audit│ │secrets   │  │
│  │ flake8   │ │          │ │ npm audit│ │TruffleHog│  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└─────────────────────────────────────────────────────────┘
                         ▲
         ┌───────────────┼──────────────────┐
         │               │                  │
  ┌──────┴──────┐ ┌──────┴──────┐ ┌────────┴────┐
  │  Python pkg │ │  npm pkg    │ │  Go CLI     │
  │  (pip)      │ │  (npx/node) │ │  (binary)   │
  └─────────────┘ └─────────────┘ └─────────────┘
         │               │                  │
  ┌──────┴──────┐ ┌──────┴──────┐ ┌────────┴────┐
  │  Shell      │ │  VS Code    │ │  Docker     │
  │  script     │ │  extension  │ │  image      │
  └─────────────┘ └─────────────┘ └─────────────┘
```

## Components

### Python Core (`packages/python/`)

The authoritative MCP server implementation. All other clients are thin wrappers that locate and spawn this process.

| File | Purpose |
|------|---------|
| `server.py` | MCP server, tool registration, request routing |
| `models.py` | `Finding`, `ScanResult`, `AggregatedReport` dataclasses |
| `utils.py` | Async subprocess runner, JSON parser, Markdown formatter |
| `tools/sast.py` | Semgrep, Bandit, ESLint-security, flake8-bandit |
| `tools/dast.py` | OWASP ZAP (Docker + local), Nikto |
| `tools/sca.py` | Trivy fs, Safety, pip-audit, npm audit |
| `tools/secrets.py` | Gitleaks, detect-secrets, TruffleHog |
| `tools/iac.py` | Checkov, Trivy config, Terrascan |

### Language Clients

Each client follows the same resolution strategy to start the server:

```
1. ARGUS_MCP_PYTHON env var  (explicit override)
2. argus-scan CLI on PATH     (pip install)
3. uvx argus-scan             (uv tool runner)
4. npx argus-scan             (npm)
5. python -m argus.server
```

### MCP Protocol

The server uses **JSON-RPC 2.0 over stdio**. Messages are newline-delimited JSON.

```
Client → Server:  { "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "scan_sast", "arguments": { "target": "/app" } } }

Server → Client:  { "jsonrpc": "2.0", "id": 1,
                    "result": { "content": [{ "type": "text", "text": "# Security Report..." }] } }
```

## Data Flow

```
User prompt → AI assistant → MCP tool call
                                  │
                          ┌───────▼────────┐
                          │  Tool handler   │
                          │  (server.py)    │
                          └───────┬────────┘
                                  │ asyncio.gather()
                     ┌────────────┼────────────┐
                     ▼            ▼            ▼
               run_semgrep   run_bandit   run_eslint
               (subprocess)  (subprocess) (subprocess)
                     │            │            │
                     └────────────┼────────────┘
                                  │
                          ┌───────▼────────┐
                          │ AggregatedReport│
                          │  (normalised)   │
                          └───────┬────────┘
                                  │
                          Markdown + JSON
                                  │
                          ← AI assistant ←
```

## Adding a New Scanner

1. Add a runner function in the appropriate `tools/*.py` file:
   ```python
   async def run_mytool(target: str, timeout: int = 120) -> ScanResult:
       result = ScanResult(tool="mytool", scan_type=ScanType.SAST, target=target)
       if not is_tool_available("mytool"):
           result.tool_available = False
           result.errors.append("mytool not installed. Install with: ...")
           return result
       code, stdout, stderr = await run_command(["mytool", "--json", target])
       # parse stdout → result.findings
       return result
   ```

2. Register it in `server.py` — add a `types.Tool(...)` entry to `list_tools()` and handle it in `call_tool()`.

3. Add it to `TOOLS_REGISTRY` in `server.py` for `check_tools` output.

4. Write a test in `tests/test_<category>.py`.
