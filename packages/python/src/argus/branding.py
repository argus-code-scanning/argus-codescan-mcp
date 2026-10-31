"""Argus name, website and icon, advertised to MCP clients in the initialize handshake."""

from __future__ import annotations

import base64
from typing import Any

WEBSITE_URL = "https://code-scan.arestechub.com/"

# Same artwork as docs/assets/argus-logo.svg.
ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<rect width="100" height="100" rx="22" fill="#E14848"/>'
    '<path d="M24 50L39.62 33.06A25 25 0 1 1 39.62 66.94Z" fill="#FFFFFF"/>'
    '<circle cx="58" cy="50" r="10" fill="#E14848"/>'
    "</svg>"
)

ICON_DATA_URI = "data:image/svg+xml;base64," + base64.b64encode(ICON_SVG.encode()).decode()


def server_branding() -> dict[str, Any]:
    """Website and icon fields for ``InitializationOptions``, when this mcp version has them.

    ``icons`` and ``website_url`` were added in later mcp releases; older ones
    reject unknown fields, so only pass what the installed version supports.
    """
    from mcp import types
    from mcp.server.models import InitializationOptions

    fields = InitializationOptions.model_fields
    extras: dict[str, Any] = {}
    if "website_url" in fields:
        extras["website_url"] = WEBSITE_URL
    if "icons" in fields and hasattr(types, "Icon"):
        extras["icons"] = [types.Icon(src=ICON_DATA_URI, mimeType="image/svg+xml", sizes=["any"])]
    return extras
