"""Static MCP documentation resources derived from the public scan models."""

from __future__ import annotations

import json
from typing import Any

from pydantic import TypeAdapter

from argus.models import Finding, ScanType

RESOURCE_DEFINITIONS = (
    ("argus://schema/finding", "Finding schema", "JSON schema for serialised Finding objects."),
    ("argus://scan-types", "Scan types", "Supported scan categories and their MCP tools."),
    ("argus://workflows", "Scan workflows", "Example read-only scan requests and review guidance."),
)

_SCAN_TOOLS = {
    "sast": "scan_sast",
    "dast": "scan_dast",
    "sca": "scan_sca",
    "secrets": "scan_secrets",
    "iac": "scan_iac",
    "container": "scan_container",
    "ml": "scan_ml",
    "malware": "scan_malware",
    "pci": "scan_pci",
}


def finding_schema() -> dict[str, Any]:
    """Return the model schema without the internal raw scanner payload."""
    schema = TypeAdapter(Finding).json_schema(mode="serialization")
    schema["properties"].pop("raw", None)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return schema


def read_resource_json(uri: str) -> str:
    """Resolve only the advertised static resource URIs to JSON text."""
    if uri == "argus://schema/finding":
        data = finding_schema()
    elif uri == "argus://scan-types":
        data = {
            "scan_types": [{"id": item.value, "tool": _SCAN_TOOLS[item.value]} for item in ScanType]
        }
    elif uri == "argus://workflows":
        data = {
            "workflows": [
                {
                    "name": "Local pre-commit review",
                    "request": {
                        "name": "review_code",
                        "arguments": {
                            "target": "/path/to/project",
                            "staged": True,
                        },
                    },
                    "guidance": "Review the findings before committing; this does not post PR comments.",
                },
                {
                    "name": "Source and dependency review",
                    "requests": [
                        {"name": "scan_sast", "arguments": {"target": "/path/to/project"}},
                        {"name": "scan_sca", "arguments": {"target": "/path/to/project"}},
                    ],
                    "guidance": "Check scanner availability and errors before interpreting an empty report.",
                },
            ],
            "notes": [
                "Reading these resources does not run scanners or access project files.",
                "Invoking scan tools may run external scanners and use their normal network access.",
                "Request explicit user approval before applying any automated fix.",
            ],
        }
    else:
        raise ValueError(f"Unknown Argus resource: {uri}")
    return json.dumps(data, indent=2)
