# Architecture

## Overview

`argus-scan` is a **Model Context Protocol (MCP) server** that exposes security scanning capabilities as structured tools an AI assistant can call. It wraps industry-standard open-source scanners behind a single, normalised interface.

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Client (AI / IDE)                 │
│   Cursor / VS Code / Claude Desktop / JetBrains / …     │
└────────────────────────┬────────────────────────────────┘
                         │  JSON-RPC 2.0 over stdio
                         │  (Content-Length framed messages)
                         ▼
┌─────────────────────────────────────────────────────────┐
│               argus-scan Server                          │
│                  (Python core)                           │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │  scan_   │ │  scan_   │ │  scan_   │ │  scan_ml  │  │
│  │  sast    │ │  sca     │ │  secrets │ │  (built-in)│  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘  │
│       │            │            │              │         │
│  ┌────▼─────┐ ┌────▼─────┐ ┌───▼──────┐ ┌────▼─────┐  │
│  │ Semgrep  │ │  Trivy   │ │Gitleaks  │ │argus-    │  │
│  │ Bandit   │ │  Safety  │ │detect-   │ │languages │  │
│  │ ESLint   │ │ pip-audit│ │secrets   │ │(ml.yaml) │  │
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
| `policy.py` | `.argus.yml` policy loader |
| `compare.py` | Baseline diff engine |
| `formatters/sarif.py` | SARIF 2.1.0 export |
| `tools/sast.py` | Semgrep, Bandit, ESLint-security, argus-languages |
| `tools/ml.py` | Built-in AI/ML & LLM pipeline rules |
| `tools/dast.py` | OWASP ZAP (Docker + local), Nikto |
| `tools/sca.py` | Trivy fs, Safety, pip-audit, npm audit |
| `tools/secrets.py` | Gitleaks, detect-secrets, TruffleHog |
| `tools/iac.py` | Checkov, Trivy config, Terrascan |
| `tools/fix.py` | `apply_fix` guidance and autofix |

### npm package (`packages/npm/`)

**Standalone Node/React scanner** — does not require Python for SCA/SAST on JS/TS projects.

| Path | Purpose |
|------|---------|
| `src/scanners/sca.ts` | npm audit integration |
| `src/scanners/sast.ts` | ESLint-security, Semgrep, opengrep |
| `src/scanners/native-sast.ts` | Bundled pattern rules |
| `bin/argus-codescan.js` | CLI entry (`npx argus-codescan scan …`) |

Optional: spawn the Python MCP server via `npx argus-codescan mcp` for full tool coverage in IDEs.

### Language Clients

Each client follows the same resolution strategy to start the server:

```
1. ARGUS_MCP_PYTHON env var  (explicit override)
2. argus-mcp / argus-scan on PATH  (pip install)
3. uvx argus-scan             (uv tool runner)
4. npx argus-codescan mcp     (npm — optional bridge to Python server)
5. python -m argus.server
```

### MCP Protocol

The server uses **JSON-RPC 2.0 over stdio** with **Content-Length framing** (MCP spec):

```
Content-Length: 123\r\n
\r\n
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}
```

Clients must send and parse framed messages. Newline-delimited JSON alone is not compatible with the Python MCP SDK server.

```
Client → Server:  tools/call { "name": "scan_sast", "arguments": { "target": "/app" } }

Server → Client:  { "result": { "content": [{ "type": "text", "text": "# Security Report..." }] } }
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
               run_semgrep   run_bandit   run_ml_scan
               (subprocess)  (subprocess) (built-in)
                     │            │            │
                     └────────────┼────────────┘
                                  │
                          ┌───────▼────────┐
                          │ AggregatedReport│
                          │  (normalised)   │
                          └───────┬────────┘
                                  │
                    Markdown / JSON / SARIF
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

For built-in YAML rules (no external tool), add a file under `packages/languages/.../bundled_rules/` and register in `rules_loader.py`.
