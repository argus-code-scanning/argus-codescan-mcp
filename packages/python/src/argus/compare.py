"""Compare scan reports for baseline diff (new / fixed / unchanged findings)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Stable hash for a finding across scans."""
    file_path = finding.get("file", "")
    normalized_path = str(Path(file_path)).replace("\\", "/") if file_path else ""
    parts = [
        finding.get("tool", ""),
        finding.get("rule_id", "") or finding.get("title", ""),
        normalized_path,
        str(finding.get("line", 0)),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _collect_findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for result in report.get("results", []):
        tool = result.get("tool", "")
        for finding in result.get("findings", []):
            enriched = dict(finding)
            enriched.setdefault("tool", tool)
            fp = finding_fingerprint(enriched)
            indexed[fp] = enriched
    return indexed


def compare_reports(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Diff two AggregatedReport JSON dicts."""
    base_map = _collect_findings(baseline)
    curr_map = _collect_findings(current)

    base_fps = set(base_map)
    curr_fps = set(curr_map)

    new_fps = curr_fps - base_fps
    fixed_fps = base_fps - curr_fps
    unchanged_fps = base_fps & curr_fps

    def _list(fps: set[str]) -> list[dict[str, Any]]:
        return [curr_map.get(fp) or base_map[fp] for fp in sorted(fps)]

    new_findings = [curr_map[fp] for fp in sorted(new_fps)]
    fixed_findings = [base_map[fp] for fp in sorted(fixed_fps)]
    unchanged_findings = [curr_map[fp] for fp in sorted(unchanged_fps)]

    return {
        "baseline_target": baseline.get("target", ""),
        "current_target": current.get("target", ""),
        "summary": {
            "new": len(new_findings),
            "fixed": len(fixed_findings),
            "unchanged": len(unchanged_findings),
            "baseline_total": len(base_map),
            "current_total": len(curr_map),
        },
        "new": new_findings,
        "fixed": fixed_findings,
        "unchanged": unchanged_findings,
    }


def report_from_new_findings_only(
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """Return a report containing only findings not in the baseline."""
    diff = compare_reports(baseline, current)
    new_fps = {finding_fingerprint(f) for f in diff["new"]}

    import copy

    report = copy.deepcopy(current)
    for result in report.get("results", []):
        result["findings"] = [
            f for f in result.get("findings", []) if finding_fingerprint(f) in new_fps
        ]
    return report
