#!/usr/bin/env sh
# argus-scan — portable shell wrapper
#
# Can be used standalone (copy to /usr/local/bin/argus-scan)
# or sourced for the helper functions.
#
# Resolution order:
#   1. $ARGUS_MCP_PYTHON / $CODETESTING_MCP_PYTHON
#   2. argus-mcp on PATH
#   3. argus / argus-scan mcp
#   4. uvx --from argus-scan argus-mcp
#   5. python3 -m argus.server
#   6. python -m argus.server

set -e

# ── Subcommands ──────────────────────────────────────────────────────────────

_check() {
  echo "Checking argus-scan availability..."
  echo ""

  # Python
  for PY in python3 python; do
    if command -v "$PY" > /dev/null 2>&1; then
      echo "✅  Python: $($PY --version)"
      break
    fi
  done

  # argus-scan package
  for PY in python3 python; do
    if command -v "$PY" > /dev/null 2>&1; then
      if "$PY" -c "import argus" 2>/dev/null; then
        VERSION=$("$PY" -c "import argus; print(argus.__version__)" 2>/dev/null || echo "unknown")
        echo "✅  argus-scan package: v${VERSION}"
      else
        echo "❌  argus-scan package not installed (pip install argus-scan)"
      fi
      break
    fi
  done

  echo ""
  echo "Security tools:"
  for TOOL in semgrep bandit flake8 eslint trivy safety gitleaks trufflehog detect-secrets checkov terrascan nikto docker; do
    if command -v "$TOOL" > /dev/null 2>&1; then
      echo "✅  ${TOOL}"
    else
      echo "❌  ${TOOL}"
    fi
  done
}

_config() {
  METHOD="${1:-uvx}"
  case "$METHOD" in
    pip)
      cat << 'JSON'
{
  "mcpServers": {
    "argus": {
      "command": "argus-mcp"
    }
  }
}
JSON
      ;;
    uvx)
      cat << 'JSON'
{
  "mcpServers": {
    "argus": {
      "command": "uvx",
      "args": ["--from", "argus-scan", "argus-mcp"]
    }
  }
}
JSON
      ;;
    npx)
      cat << 'JSON'
{
  "mcpServers": {
    "argus": {
      "command": "npx",
      "args": ["-y", "argus-codescan", "mcp"]
    }
  }
}
JSON
      ;;
    docker)
      cat << 'JSON'
{
  "mcpServers": {
    "argus": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "${PWD}:/workspace", "ghcr.io/okirigabriel/argus-codescan-mcp:latest"]
    }
  }
}
JSON
      ;;
    *)
      echo "Unknown method: $METHOD. Choose: pip, uvx, npx, docker" >&2
      exit 1
      ;;
  esac
}

_help() {
  cat << 'HELP'
argus-scan — MCP server for code security testing

USAGE:
  argus-scan [command]

COMMANDS:
  (none)           Start the MCP server (stdio transport)
  check            Check Python server and tool availability
  config [method]  Print MCP client config JSON (pip|uvx|npx|docker)
  help             Show this help

ENVIRONMENT:
  ARGUS_MCP_PYTHON   Override the server executable path

EXAMPLES:
  argus-scan check
  argus-scan config uvx
  argus-scan config npx

INSTALL:
  curl -sSfL https://raw.githubusercontent.com/OkiriGabriel/argus-codescan-mcp/main/packages/shell/install.sh | sh

TOOLS PROVIDED (via MCP):
  scan_sast        Semgrep, Bandit, ESLint-security
  scan_dast        OWASP ZAP, Nikto
  scan_sca         Trivy, Safety, pip-audit, npm audit
  scan_secrets     Gitleaks, detect-secrets, TruffleHog
  scan_iac         Checkov, Trivy config, Terrascan
  scan_container   Trivy image
  scan_all         All of the above
  check_tools      List available scanners
HELP
}

# ── Main dispatch ─────────────────────────────────────────────────────────────

case "${1:-}" in
  check)   _check ;;
  config)  _config "${2:-uvx}" ;;
  help|--help|-h) _help ;;
  --version|-v)
    for PY in python3 python; do
      if command -v "$PY" > /dev/null 2>&1; then
        "$PY" -c "import argus; print('argus-scan', argus.__version__)" 2>/dev/null && exit 0
      fi
    done
    echo "argus-scan (version unknown — package not installed)"
    ;;
  "")
    # Default: start the server

    # Resolution order
    if [ -n "$ARGUS_MCP_PYTHON" ]; then
      exec "$ARGUS_MCP_PYTHON"
    fi
    if [ -n "$CODETESTING_MCP_PYTHON" ]; then
      exec "$CODETESTING_MCP_PYTHON"
    fi

    if command -v argus-mcp > /dev/null 2>&1; then
      exec argus-mcp
    fi

    for CMD in argus argus-scan; do
      if command -v "$CMD" > /dev/null 2>&1 && [ "$(basename "$0")" != "$CMD" ]; then
        exec "$CMD" mcp
      fi
    done

    if command -v uvx > /dev/null 2>&1; then
      exec uvx --from argus-scan argus-mcp
    fi

    for PY in python3 python; do
      if command -v "$PY" > /dev/null 2>&1; then
        exec "$PY" -m argus.server
      fi
    done

    echo "ERROR: argus-scan Python server not found." >&2
    echo "Install with: pip install argus-scan" >&2
    echo "Or run: curl -sSfL https://raw.githubusercontent.com/OkiriGabriel/argus-codescan-mcp/main/packages/shell/install.sh | sh" >&2
    exit 1
    ;;
  *)
    echo "Unknown command: $1" >&2
    _help >&2
    exit 1
    ;;
esac
