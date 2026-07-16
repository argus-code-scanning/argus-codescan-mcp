# argus-scan (Go)

A single-binary Go CLI that locates and spawns the argus-scan Python MCP server. Useful when you want a pre-compiled binary with no runtime dependency on Python or Node.js being in the PATH.

## Install

### Homebrew (macOS/Linux)
```bash
brew install GabrielOkiri/tap/argus
```

### Go install
```bash
go install github.com/OkiriGabriel/argus-codescan-mcp/cmd/argus@latest

# Or build from a clone:
cd packages/go
go install ./cmd/argus
```

> Note: the Go module lives under `packages/go`. From a clone, always build inside that directory.

### Pre-built binaries

Download from the [GitHub Releases](https://github.com/OkiriGabriel/argus-codescan-mcp/releases) page:

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `argus-scan-darwin-arm64` |
| macOS (Intel) | `argus-scan-darwin-amd64` |
| Linux x86_64 | `argus-scan-linux-amd64` |
| Linux ARM64 | `argus-scan-linux-arm64` |
| Windows x86_64 | `argus-scan-windows-amd64.exe` |

## Usage

```bash
argus-scan              # Start MCP server (default)
argus-scan check        # Check Python server availability
argus-scan config       # Print MCP config JSON (default: uvx)
argus-scan config -m pip  # Print config for pip install
argus-scan --version    # Show version
argus-scan --help       # Show help
```

## MCP Client Config

```bash
argus-scan config       # prints ready-to-paste JSON
```

Example output:
```json
{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["--from", "argus-scan", "argus-mcp"]
    }
  }
}
```

## Server Resolution

The binary finds the Python server in this order:

1. `ARGUS_MCP_PYTHON` / `CODETESTING_MCP_PYTHON` environment variable
2. `argus-mcp` on PATH (from `pip install argus-scan`)
3. `argus` / `argus-scan mcp` on PATH
4. `uvx --from argus-scan argus-mcp`
5. `python3 -m argus.server` / `python -m argus.server`

## Build from Source

```bash
git clone https://github.com/OkiriGabriel/argus-codescan-mcp
cd packages/go
go build ./cmd/argus
```

Cross-compile:
```bash
GOOS=linux GOARCH=amd64 go build -o argus-scan-linux-amd64 ./cmd/argus
GOOS=darwin GOARCH=arm64 go build -o argus-scan-darwin-arm64 ./cmd/argus
GOOS=windows GOARCH=amd64 go build -o argus-scan-windows-amd64.exe ./cmd/argus
```
