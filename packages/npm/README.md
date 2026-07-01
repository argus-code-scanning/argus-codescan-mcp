# argus-scan (npm)

Node.js wrapper for the [argus-scan](https://pypi.org/project/argus-scan/) Python MCP server.

## Installation

```bash
npm install -g argus-scan
```

Or use without installation via `npx`:

```bash
npx argus-scan
```

## Usage as MCP Server

Add to your MCP client config (e.g. `~/.cursor/mcp.json` or Claude Desktop):

```json
{
  "mcpServers": {
    "argus-scan": {
      "command": "npx",
      "args": ["-y", "argus-scan"]
    }
  }
}
```

With `uvx` (recommended — no npm/pip install needed):

```json
{
  "mcpServers": {
    "argus-scan": {
      "command": "uvx",
      "args": ["argus-scan"]
    }
  }
}
```

## CLI Commands

```bash
argus-scan              # Start MCP server (default)
argus-scan --check      # Check Python server availability
argus-scan --config uvx # Print MCP config JSON for uvx
argus-scan --help       # Show help
```

## Programmatic Use

```typescript
import { spawnPythonMcpServer, checkPythonServerAvailable } from "argus-scan";

// Check availability
const { available, command } = await checkPythonServerAvailable();

// Spawn and communicate
const proc = await spawnPythonMcpServer();
// proc.stdin/stdout/stderr are available for MCP communication
```

## Requirements

This package requires the Python `argus-scan` package to be installed:

```bash
pip install argus-scan
```

Or use `uvx` which handles this automatically.
