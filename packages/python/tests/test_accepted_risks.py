"""Accepted risks in .argus.yml: kept in the report, excluded from --fail-on until they expire."""

from __future__ import annotations

from datetime import date, timedelta

from argus.cli import _count_failing
from argus.policy import PolicyConfig, _apply_accepted_risks, apply_policy, finding_ids

TODAY = date.today()


def _report(*findings: dict) -> dict:
    return {"target": ".", "results": [{"tool": "npm-audit", "findings": list(findings)}]}


PICOMATCH = {
    "title": "picomatch vulnerable to ReDoS",
    "severity": "high",
    "tool": "npm-audit",
    "file": "package-lock.json",
    "rule_id": "GHSA-fc5q-39xc-vjpf",
    "package": "picomatch",
}
GROUPED = {  # one osv-deps finding covering several advisories
    "title": "nokogiri: 3 known vulnerabilities",
    "severity": "critical",
    "tool": "osv-deps",
    "file": "Gemfile.lock",
    "rule_id": "GHSA-353f-x4gh-cqq8",
    "cve": "CVE-2022-24836",
    "description": "[runtime dependency] Ruby package nokogiri 1.13.0: GHSA-353f-x4gh-cqq8, "
    "GHSA-59gp-qqm7-cw4j, GHSA-c4rq-3m3g-8wgx",
    "package": "nokogiri",
}
OTHER = {
    "title": "lodash",
    "severity": "high",
    "tool": "npm-audit",
    "rule_id": "GHSA-35jh-r3h4-6jhm",
}


def _policy(*risks: dict) -> PolicyConfig:
    return PolicyConfig.from_dict({"accepted_risks": list(risks)})


def _in(days: int) -> str:
    return (TODAY + timedelta(days=days)).isoformat()


def test_accepted_finding_stays_visible_but_does_not_fail() -> None:
    policy = _policy({"id": "GHSA-fc5q-39xc-vjpf", "reason": "no fix yet", "expires": _in(30)})
    report = apply_policy(_report(dict(PICOMATCH), dict(OTHER)), policy)
    findings = report["results"][0]["findings"]
    assert len(findings) == 2  # never hidden
    assert findings[0]["accepted_risk"] == {
        "id": "GHSA-fc5q-39xc-vjpf",
        "reason": "no fix yet",
        "expires": _in(30),
    }
    assert _count_failing(report, "high") == 1  # only lodash
    assert "policy_notes" not in report


def test_expired_risk_fails_again_with_a_note() -> None:
    policy = _policy({"id": "GHSA-fc5q-39xc-vjpf", "reason": "no fix yet", "expires": _in(-1)})
    report = apply_policy(_report(dict(PICOMATCH)), policy)
    [finding] = report["results"][0]["findings"]
    assert "accepted_risk" not in finding
    assert finding["accepted_risk_expired"] == _in(-1)
    assert _count_failing(report, "high") == 1
    assert report["policy_notes"][0].startswith(
        f"Accepted risk GHSA-fc5q-39xc-vjpf expired on {_in(-1)} and counts again"
    )


def test_matches_any_advisory_in_a_grouped_finding() -> None:
    assert "GHSA-59gp-qqm7-cw4j" in finding_ids(GROUPED)
    assert "CVE-2022-24836" in finding_ids(GROUPED)
    report = apply_policy(
        _report(dict(GROUPED)), _policy({"id": "GHSA-59gp-qqm7-cw4j", "expires": _in(60)})
    )
    assert report["results"][0]["findings"][0]["accepted_risk"]["id"] == "GHSA-59gp-qqm7-cw4j"


def test_package_must_match_when_given() -> None:
    risk = {"id": "GHSA-fc5q-39xc-vjpf", "package": "micromatch", "expires": _in(30)}
    report = apply_policy(_report(dict(PICOMATCH)), _policy(risk))
    assert "accepted_risk" not in report["results"][0]["findings"][0]


def test_notes_for_missing_expiry_unused_and_expiring_soon() -> None:
    report = _report(dict(PICOMATCH), dict(OTHER))
    notes = _apply_accepted_risks(
        report,
        _policy(
            {"id": "GHSA-fc5q-39xc-vjpf", "reason": "no fix yet", "expires": _in(3)},
            {"id": "GHSA-35jh-r3h4-6jhm"},  # no expiry
            {"id": "GHSA-xxxx-xxxx-xxxx", "expires": _in(90)},  # fixed meanwhile
        ).accepted_risks,
    )
    assert notes == [
        "Accepted risk GHSA-35jh-r3h4-6jhm is ignored: add expires: YYYY-MM-DD (and a reason) "
        "so it gets reviewed.",
        f"Accepted risk GHSA-fc5q-39xc-vjpf expires in 3 days ({_in(3)}) (no fix yet).",
        "Accepted risk GHSA-xxxx-xxxx-xxxx matched no finding: it may be fixed; remove it from "
        ".argus.yml.",
    ]
    assert "accepted_risk" not in report["results"][0]["findings"][1]  # no expiry: not accepted
