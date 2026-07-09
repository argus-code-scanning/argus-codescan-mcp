#!/bin/sh
set -e

# Default: MCP server over stdio (for Cursor, Claude Desktop, etc.)
if [ "$#" -eq 0 ] || [ "$1" = "mcp" ]; then
  exec python -m argus.server
fi

# CLI: argus scan / argus tools / etc.
exec argus "$@"
