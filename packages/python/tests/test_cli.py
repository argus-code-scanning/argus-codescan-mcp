

def test_low_confidence_findings_do_not_fail_by_default(capsys):
    from argus.cli import _emit

    report = {
        "target": ".",
        "results": [
            {
                "tool": "argus-languages",
                "findings": [
                    {"title": "Knex raw", "severity": "high", "confidence": "low", "file": "a.js"},
                ],
            }
        ],
    }
    assert _emit(report, "json", None, "low", "high") == 0
    assert "low-confidence" in capsys.readouterr().err
    assert _emit(report, "json", None, "low", "high", include_low_confidence=True) == 1

    report["results"][0]["findings"][0]["confidence"] = "medium"
    assert _emit(report, "json", None, "low", "high") == 1


def test_scan_status_ignores_low_confidence():
    from argus.cloud_upload import scan_status

    low = {"results": [{"findings": [{"severity": "high", "confidence": "low"}]}]}
    assert scan_status(low, "high") == "passed"
    low["results"][0]["findings"][0]["confidence"] = ""
    assert scan_status(low, "high") == "failed"


def test_policy_fail_on_low_confidence():
    from argus.policy import PolicyConfig

    assert PolicyConfig.from_dict({"fail_on_low_confidence": True}).fail_on_low_confidence
    assert not PolicyConfig.from_dict({}).fail_on_low_confidence
