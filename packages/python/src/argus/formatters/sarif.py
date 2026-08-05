"""SARIF 2.1.0 export for GitHub Code Scanning integration."""

from __future__ import annotations

from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-open/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEV_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "none",
}


def _severity_level(severity: str) -> str:
    return _SEV_TO_SARIF.get(severity.lower(), "warning")


def _rule_key(finding: dict[str, Any]) -> str:
    tool = finding.get("tool", "argus")
    rule_id = finding.get("rule_id") or finding.get("title", "finding")
    return f"{tool}/{rule_id}"


def aggregated_report_to_sarif(report_dict: dict[str, Any]) -> dict[str, Any]:
    """Convert an AggregatedReport dict to SARIF 2.1.0."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for scan_result in report_dict.get("results", []):
        tool_name = scan_result.get("tool", "argus")
        for finding in scan_result.get("findings", []):
            key = _rule_key(finding)
            if key not in rules:
                rules[key] = {
                    "id": key,
                    "name": finding.get("rule_id") or finding.get("title", "finding"),
                    "shortDescription": {"text": finding.get("title", "Security finding")},
                    "fullDescription": {
                        "text": finding.get("description") or finding.get("title", "")
                    },
                    "help": {
                        "text": finding.get("fix_guidance") or finding.get("description", ""),
                        "markdown": finding.get("fix_guidance") or finding.get("description", ""),
                    },
                    "properties": {
                        "tags": [finding.get("scan_type", "security")],
                        **({"security-severity": _security_severity(finding.get("severity", ""))}),
                    },
                }
                if finding.get("cwe"):
                    rules[key]["properties"]["tags"].append(finding["cwe"])

            location: dict[str, Any] = {}
            file_path = finding.get("file", "")
            if file_path:
                region: dict[str, Any] = {}
                line = finding.get("line", 0)
                if line:
                    region["startLine"] = line
                    region["startColumn"] = max(finding.get("column", 0), 1) or 1
                location["physicalLocation"] = {
                    "artifactLocation": {"uri": file_path},
                    **({"region": region} if region else {}),
                }

            result_entry: dict[str, Any] = {
                "ruleId": key,
                "level": _severity_level(finding.get("severity", "unknown")),
                "message": {
                    "text": finding.get("description") or finding.get("title", "Security finding"),
                },
                "properties": {
                    "severity": finding.get("severity", "unknown"),
                    "scan_type": finding.get("scan_type", ""),
                    "tool": tool_name,
                },
            }
            if location:
                result_entry["locations"] = [location]
            if finding.get("cwe"):
                result_entry["properties"]["cwe"] = finding["cwe"]
            if finding.get("cve"):
                result_entry["properties"]["cve"] = finding["cve"]

            results.append(result_entry)

    driver_rules = list(rules.values())
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "argus-scan",
                "informationUri": "https://github.com/argus-code-scanning/argus-codescan-mcp",
                "rules": driver_rules,
            }
        },
        "results": results,
    }
    if report_dict.get("target"):
        run["properties"] = {"target": report_dict["target"]}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _security_severity(severity: str) -> str:
    """GitHub security-severity: 0.0–10.0 string."""
    mapping = {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.0",
        "info": "0.0",
    }
    return mapping.get(severity.lower(), "5.0")
