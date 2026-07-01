# argus-scan (Shell)

A POSIX shell wrapper that works on any Unix-like system with no dependencies beyond Python 3.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/GabrielOkiri/argus-mcp/main/packages/shell/install.sh | sh
```

Or manually:

```bash
curl -sSfL https://raw.githubusercontent.com/GabrielOkiri/argus-mcp/main/packages/shell/argus-scan.sh \
  -o /usr/local/bin/argus-scan
chmod +x /usr/local/bin/argus-scan
pip install argus-scan
```

## Usage

```bash
argus-scan              # Start MCP server
argus-scan check        # Check tool availability
argus-scan config uvx   # Print MCP config JSON
argus-scan --help       # Show help
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ARGUS_MCP_PYTHON` | Override the Python server path |
