"""Request input in HTTP response headers and email headers (#187)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

IDS = {r.id for r in load_rules_from_files(("header-injection.yaml",))}


def found(tmp_path: Path, name: str, code: str) -> set[str]:
    (tmp_path / name).write_text(code + "\n")
    return {f.rule_id for f in scan_directory(tmp_path).findings if f.rule_id in IDS}


def test_pack_registered() -> None:
    assert "header-injection.yaml" in RULE_FILES
    assert all(r.fix_guidance for r in load_rules_from_files(("header-injection.yaml",)))


@pytest.mark.parametrize(
    ("name", "code", "rule"),
    [
        (
            "app.py",
            'resp.headers["X-Name"] = request.args["name"]',
            "py-response-header-from-request",
        ),
        (
            "views.py",
            'response["X-Request"] = request.GET.get("r")',
            "py-response-header-from-request",
        ),
        ("mail.py", 'msg["To"] = request.form["to"]', "py-email-header-from-request"),
        ("mail.py", 'msg["Subject"] = request.form["s"]', "py-email-header-from-request"),
        ("app.js", 'res.setHeader("X-User", req.body.user);', "js-response-header-from-request"),
        (
            "app.ts",
            "res.set('X-Trace', req.headers['x-trace']);",
            "js-response-header-from-request",
        ),
        (
            "mail.js",
            "transporter.sendMail({ to: req.body.to, subject: s, text });",
            "js-email-from-request",
        ),
        (
            "contact.php",
            "<?php mail($_POST['to'], $_POST['subject'], $body, 'From: ' . $_POST['from']);",
            "php-mail-header-injection",
        ),
        ("h.php", "<?php header('X-Name: ' . $_GET['name']);", "php-header-from-request"),
        (
            "A.java",
            'response.setHeader("X-Name", request.getParameter("name"));',
            "java-response-header-from-request",
        ),
        (
            "A.java",
            'response.addCookie(new Cookie("lang", request.getParameter("lang")));',
            "java-response-header-from-request",
        ),
        (
            "M.java",
            'message.setSubject(request.getParameter("subject"));',
            "java-email-header-from-request",
        ),
        (
            "dl.py",
            'resp.headers["Content-Disposition"] = "attachment; filename=" + request.args["f"]',
            "content-disposition-filename-from-request",
        ),
    ],
)
def test_flags(tmp_path: Path, name: str, code: str, rule: str) -> None:
    assert rule in found(tmp_path, name, code)


@pytest.mark.parametrize(
    ("name", "code"),
    [
        # Location is an open redirect (#196), not reported twice
        ("app.js", 'res.setHeader("Location", req.query.next);'),
        ("h.php", "<?php header('Location: ' . $_GET['url']);"),
        # sanitised / encoded
        (
            "app.py",
            'resp.headers["X-Name"] = request.args["name"].replace("\\r", "").replace("\\n", "")',
        ),
        (
            "dl.py",
            'resp.headers["Content-Disposition"] = "attachment; filename=" + quote(request.args["f"])',  # noqa: E501
        ),
        ("app.js", 'res.setHeader("X-Q", encodeURIComponent(req.query.q));'),
        ("contact.php", "<?php mail(filter_var($_POST['to'], FILTER_VALIDATE_EMAIL), $s, $body);"),
        # not request input
        ("app.py", 'resp.headers["X-Version"] = VERSION'),
        ("mail.js", "transporter.sendMail({ to: user.email, subject: 'Welcome' });"),
        ("A.java", 'response.setHeader("Cache-Control", "no-store");'),
        ("mail.py", 'msg["To"] = current_user.email'),
    ],
)
def test_safe(tmp_path: Path, name: str, code: str) -> None:
    assert found(tmp_path, name, code) == set()
