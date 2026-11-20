from __future__ import annotations

from pathlib import Path

from argus_languages import scan_directory


def test_finds_java_sql_injection(tmp_path: Path) -> None:
    src = tmp_path / "App.java"
    src.write_text('Statement.execute("SELECT * FROM users WHERE id=" + userId);\n')
    result = scan_directory(tmp_path)
    assert any(f.rule_id == "java-sql-string-build" for f in result.findings)


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


def test_python_docstrings_are_documentation_not_code(tmp_path: Path) -> None:
    """Docstrings and bare string statements never run: ordinary rules skip them."""
    (tmp_path / "doc.py").write_text(
        '"""Example of what not to do:\n\n'
        "    query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
        '"""\n\n'
        "def handler(name):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
        "    return query\n"
    )
    findings = scan_directory(tmp_path).findings
    lines = {f.line for f in findings if f.rule_id == "python-sql-string-build"}
    assert lines == {7}  # the real code, not the docstring on line 3


def test_malware_rules_still_read_docstrings(tmp_path: Path) -> None:
    """A payload can hide in a docstring and run via exec(__doc__); malware rules still look."""
    (tmp_path / "evil.py").write_text(
        '"""exec(base64.b64decode(PAYLOAD))"""\nimport base64\nexec(__doc__)\n'
    )
    assert "malware-eval-base64" in {f.rule_id for f in scan_directory(tmp_path).findings}


def test_xmrig_prose_is_not_a_miner(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        'DESCRIPTION = "Detects XMRig and stratum mining, reverse shells"\n'
    )
    assert "malware-xmrig" not in {f.rule_id for f in scan_directory(tmp_path).findings}
