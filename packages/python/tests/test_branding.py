"""MCP server branding: website and icon in the initialize handshake."""

from __future__ import annotations

import base64
import re
from pathlib import Path

from argus.branding import ICON_DATA_URI, ICON_SVG, WEBSITE_URL, server_branding

DOCS_LOGO = Path(__file__).resolve().parents[3] / "docs" / "assets" / "argus-logo.svg"


def _shapes(svg: str) -> list[str]:
    """The drawing elements, ignoring whitespace and accessibility attributes."""
    return re.findall(r"<(?:rect|path|circle)\b[^>]*/>", re.sub(r"\s+", " ", svg))


def test_icon_matches_docs_logo():
    assert _shapes(ICON_SVG) == _shapes(DOCS_LOGO.read_text())


def test_icon_data_uri_decodes_to_svg():
    prefix, payload = ICON_DATA_URI.split(",", 1)
    assert prefix == "data:image/svg+xml;base64"
    assert base64.b64decode(payload).decode() == ICON_SVG


def test_server_branding_passes_supported_fields():
    from mcp.server.models import InitializationOptions

    branding = server_branding()
    if "website_url" in InitializationOptions.model_fields:
        assert branding["website_url"] == WEBSITE_URL
    if "icons" in InitializationOptions.model_fields:
        assert branding["icons"][0].src == ICON_DATA_URI
    # Must always be accepted by the installed mcp version.
    InitializationOptions(server_name="argus-scan", server_version="0", capabilities={}, **branding)
