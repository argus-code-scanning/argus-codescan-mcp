#!/usr/bin/env sh
# argus-scan installer
# Usage: curl -sSfL https://raw.githubusercontent.com/OkiriGabriel/argus-codescan-mcp/main/packages/shell/install.sh | sh
#        Or with options: curl ... | sh -s -- --prefix /usr/local

set -e

PREFIX="${PREFIX:-/usr/local}"
SCRIPT_NAME="argus-scan"
REPO="OkiriGabriel/argus-codescan-mcp"
MAIN_BRANCH="main"

# ── Helpers ─────────────────────────────────────────────────────────────────

info()  { printf '\033[0;34m  INFO\033[0m  %s\n' "$*"; }
ok()    { printf '\033[0;32m    OK\033[0m  %s\n' "$*"; }
warn()  { printf '\033[0;33m  WARN\033[0m  %s\n' "$*"; }
error() { printf '\033[0;31m ERROR\033[0m  %s\n' "$*" >&2; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────────────

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: install.sh [--prefix DIR]"
      echo "  --prefix DIR   Install to DIR/bin (default: /usr/local)"
      exit 0 ;;
    *) error "Unknown option: $1" ;;
  esac
done

BIN_DIR="${PREFIX}/bin"

# ── Pre-flight checks ────────────────────────────────────────────────────────

info "Installing ${SCRIPT_NAME} to ${BIN_DIR}"

# Check Python
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" > /dev/null 2>&1; then
    PYTHON="$candidate"
    break
  fi
done
[ -z "$PYTHON" ] && error "Python 3 is required but not found. Install from https://python.org"

PYTHON_VERSION=$("$PYTHON" -c "import sys; print(sys.version_info.major, sys.version_info.minor)")
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d' ' -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d' ' -f2)
[ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]) \
  && error "Python 3.10+ required. Found: $($PYTHON --version)"
ok "Python found: $($PYTHON --version)"

# ── Install Python package ────────────────────────────────────────────────────

info "Installing argus-scan Python package..."
if command -v uv > /dev/null 2>&1; then
  uv pip install argus-scan || error "uv pip install failed"
  ok "Installed via uv"
else
  "$PYTHON" -m pip install --quiet argus-scan || error "pip install failed"
  ok "Installed via pip"
fi

# ── Install wrapper script ────────────────────────────────────────────────────

info "Installing wrapper script to ${BIN_DIR}/${SCRIPT_NAME}..."
mkdir -p "$BIN_DIR"

cat > "${BIN_DIR}/${SCRIPT_NAME}" << 'WRAPPER'
#!/usr/bin/env sh
# argus-scan — wrapper script
# Locates and starts the Python MCP server.

set -e

# 1. Explicit override
if [ -n "$ARGUS_MCP_PYTHON" ]; then
  exec "$ARGUS_MCP_PYTHON" "$@"
fi
if [ -n "$CODETESTING_MCP_PYTHON" ]; then
  exec "$CODETESTING_MCP_PYTHON" "$@"
fi

# 2. Dedicated MCP entrypoint (pip install)
if command -v argus-mcp > /dev/null 2>&1; then
  exec argus-mcp "$@"
fi

# 3. CLI with mcp subcommand
for CMD in argus argus-scan; do
  if command -v "$CMD" > /dev/null 2>&1 && [ "$(command -v "$CMD")" != "$0" ]; then
    exec "$CMD" mcp "$@"
  fi
done

# 4. uvx
if command -v uvx > /dev/null 2>&1; then
  exec uvx --from argus-scan argus-mcp "$@"
fi

# 5. python module
for PY in python3 python; do
  if command -v "$PY" > /dev/null 2>&1; then
    exec "$PY" -m argus.server "$@"
  fi
done

echo "ERROR: argus-scan Python server not found." >&2
echo "Install with: pip install argus-scan" >&2
exit 1
WRAPPER

chmod +x "${BIN_DIR}/${SCRIPT_NAME}"
ok "Wrapper script installed: ${BIN_DIR}/${SCRIPT_NAME}"

# ── Verify ───────────────────────────────────────────────────────────────────

if ! command -v "${SCRIPT_NAME}" > /dev/null 2>&1; then
  warn "${BIN_DIR} may not be in your PATH."
  warn "Add to your shell profile: export PATH=\"${BIN_DIR}:\$PATH\""
fi

echo ""
ok "argus-scan installed successfully!"
echo ""
echo "Repo: https://github.com/${REPO} (${MAIN_BRANCH})"
echo ""
echo "Next steps:"
echo "  1. Install scanners:"
echo "     pip install semgrep bandit safety pip-audit detect-secrets checkov"
echo "     brew install trivy gitleaks  # macOS"
echo ""
echo "  2. Add to your MCP client config (~/.cursor/mcp.json):"
cat << 'JSON'
     {
       "mcpServers": {
         "argus": {
           "command": "argus-mcp"
         }
       }
     }
JSON
echo ""
echo "  3. Verify: argus tools"
echo ""
