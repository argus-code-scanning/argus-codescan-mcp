"""Python access-control rules: Django REST Framework, Django CSRF and Flask-Login."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

ACCESS_CONTROL_RULES = {
    "python-drf-allowany-view",
    "python-drf-empty-auth",
    "python-drf-default-allowany",
    "python-django-csrf-exempt",
    "python-flask-login-disabled",
}


def _findings(tmp_path: Path, code: str, name: str = "views.py") -> dict[str, str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return {
        f.rule_id: str(f.severity.value)
        for f in scan_directory(tmp_path).findings
        if f.rule_id in ACCESS_CONTROL_RULES
    }


def test_rule_pack_is_registered_and_complete() -> None:
    assert "access-control.yaml" in RULE_FILES
    rules = load_rules_from_files(("access-control.yaml",))
    assert {r.id for r in rules} == ACCESS_CONTROL_RULES
    for rule in rules:
        assert rule.languages == ["python"]
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"


@pytest.mark.parametrize(
    ("code", "rule", "severity"),
    [
        ("permission_classes = [AllowAny]", "python-drf-allowany-view", "medium"),
        ("permission_classes = (permissions.AllowAny,)", "python-drf-allowany-view", "medium"),
        ("permission_classes=[AllowAny, IsAdminUser]", "python-drf-allowany-view", "medium"),
        ("@permission_classes([AllowAny])", "python-drf-allowany-view", "medium"),
        ("@permission_classes((AllowAny,))", "python-drf-allowany-view", "medium"),
        ("permission_classes = []", "python-drf-allowany-view", "medium"),
        ("authentication_classes = []", "python-drf-empty-auth", "medium"),
        ("authentication_classes = ()", "python-drf-empty-auth", "medium"),
        ("@authentication_classes([])", "python-drf-empty-auth", "medium"),
        (
            "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': "
            "['rest_framework.permissions.AllowAny']}",
            "python-drf-default-allowany",
            "high",
        ),
        (
            "    'DEFAULT_PERMISSION_CLASSES': [\n"
            "        'rest_framework.permissions.AllowAny',\n"
            "    ],",
            "python-drf-default-allowany",
            "high",
        ),
        ("@csrf_exempt", "python-django-csrf-exempt", "medium"),
        ("@method_decorator(csrf_exempt, name='dispatch')", "python-django-csrf-exempt", "medium"),
        (
            "urlpatterns = [path('hook/', csrf_exempt(webhook))]",
            "python-django-csrf-exempt",
            "medium",
        ),
        ('app.config["LOGIN_DISABLED"] = True', "python-flask-login-disabled", "high"),
        ("app.config['LOGIN_DISABLED'] = True", "python-flask-login-disabled", "high"),
        ("LOGIN_DISABLED = True", "python-flask-login-disabled", "high"),
    ],
)
def test_vulnerable_code_is_flagged(tmp_path: Path, code: str, rule: str, severity: str) -> None:
    found = _findings(tmp_path, f"{code}\n")
    assert rule in found
    assert found[rule] == severity


@pytest.mark.parametrize(
    "code",
    [
        "permission_classes = [IsAuthenticated]",
        "permission_classes = [IsAuthenticated, IsAdminUser]",
        "permission_classes = (permissions.IsAuthenticated,)",
        "@permission_classes([IsAuthenticated])",
        "authentication_classes = [TokenAuthentication, SessionAuthentication]",
        "@authentication_classes([TokenAuthentication])",
        "'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']",
        "class AllowAnyAccessLog:\n    pass",
        "@csrf_protect",
        "@login_required",
        "from django.views.decorators.csrf import csrf_exempt",
        "import csrf_exempt_helpers",
        "# we never use csrf_exempt here",
        "app.config['LOGIN_DISABLED'] = False",
        "login_disabled = True",
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, code: str) -> None:
    assert _findings(tmp_path, f"{code}\n") == {}


def test_rules_only_apply_to_python_files(tmp_path: Path) -> None:
    assert _findings(tmp_path, "permission_classes = [AllowAny]\n", name="notes.txt") == {}
    assert _findings(tmp_path, "LOGIN_DISABLED = True\n", name="app.js") == {}
