from __future__ import annotations

from pathlib import Path

from argus_languages import scan_directory


def test_finds_java_sql_injection(tmp_path: Path) -> None:
    src = tmp_path / "App.java"
    src.write_text('Statement.execute("SELECT * FROM users WHERE id=" + userId);\n')
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "sql-concat" for f in result.findings)


def test_finds_terraform_public_sg(tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_security_group" "web" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "tf-open-security-group" for f in result.findings)


def test_finds_ansible_hardcoded_password(tmp_path: Path) -> None:
    playbook = tmp_path / "playbooks" / "site.yml"
    playbook.parent.mkdir()
    playbook.write_text("- hosts: all\n  vars:\n    db_password: \"supersecret123\"\n")
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "ansible-hardcoded-secret" for f in result.findings)


def test_finds_php_include(tmp_path: Path) -> None:
    php = tmp_path / "index.php"
    php.write_text("<?php include($_GET['page']); ?>\n")
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "php-include-user-input" for f in result.findings)
