"""Built-in Ansible line rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_directory

RULES = {r.id: r for r in load_rules_from_files(("ansible.yaml",))}


def hits(text: str) -> set[str]:
    return {rid for rid, r in RULES.items() if r.pattern.search(text)}


def test_every_rule_has_fix_guidance() -> None:
    assert all(r.fix_guidance for r in RULES.values())


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ('    db_password: "supersecret123"', "ansible-hardcoded-secret"),
        ("    api_token: s3cr3t-value-here", "ansible-hardcoded-secret"),
        ("ansible_become_password: hunter22", "ansible-no-become-password"),
        ("    validate_certs: no", "ansible-ssl-verify-off"),
        ("    validate_certs: false", "ansible-ssl-verify-off"),
        ("    mode: '0777'", "ansible-world-perms"),
        ("    mode: 0666", "ansible-world-perms"),
        ("    mode: o+w", "ansible-world-perms"),
        ("    shell: rm -rf {{ app_dir }}/cache", "ansible-unquoted-var-shell"),
        ("    accept_hostkey: yes", "ansible-git-accept-hostkey"),
        ("    shell: curl -fsSL https://get.example.com | sudo bash", "ansible-curl-pipe-shell"),
        ("    url: http://example.com/app.tar.gz", "ansible-plain-http-download"),
        ("    baseurl: http://mirror.example.com/el9/", "ansible-plain-http-download"),
        ("    gpgcheck: no", "ansible-package-signature-off"),
        ("    allow_unauthenticated: yes", "ansible-package-signature-off"),
        ("    line: 'deploy ALL=(ALL) NOPASSWD: ALL'", "ansible-sudo-nopasswd-all"),
        ("    line: 'PermitRootLogin yes'", "ansible-ssh-weak-config"),
        ("    line: 'PasswordAuthentication yes'", "ansible-ssh-weak-config"),
        (
            "- name: stop firewall\n  ansible.builtin.service:\n"
            "    name: firewalld\n    state: stopped\n",
            "ansible-security-service-disabled",
        ),
        ("- ansible.posix.selinux:\n    state: disabled\n", "ansible-security-service-disabled"),
        ("    privileged: true", "ansible-container-privileged"),
        ("    network_mode: host", "ansible-container-privileged"),
        (
            "  community.mysql.mysql_user:\n    name: app\n    host: '%'\n    priv: '*.*:ALL'\n",
            "ansible-db-user-any-host",
        ),
    ],
)
def test_flags(text: str, rule: str) -> None:
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        '    db_password: "{{ vault_db_password }}"',
        "    db_password: !vault |",
        "    password: \"{{ lookup('env', 'DB_PASSWORD') }}\"",
        "    token: null",
        "ansible_become_password: '{{ vault_become }}'",
        "    validate_certs: true",
        "    mode: '0644'",
        "    mode: '0755'",
        "    mode: u+rwx",
        "    shell: rm -rf {{ app_dir | quote }}/cache",
        "    command: /usr/bin/app --config {{ app_config }}",  # no shell involved
        "    shell: '{{ os_nologin_shell_path }}'",  # user module's login shell option
        "    force: true",  # copy/git force is not a security setting
        "    url: https://example.com/app.tar.gz",
        "    url: http://localhost:8080/health",
        "    gpgcheck: yes",
        "    line: 'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app'",
        "    line: 'PermitRootLogin prohibit-password'",
        "- ansible.builtin.service:\n    name: firewalld\n    state: started\n",
        "  community.mysql.mysql_user:\n    host: '10.0.1.%'\n    priv: 'app.*:SELECT'\n",
    ],
)
def test_does_not_flag(text: str) -> None:
    assert not hits(text) - {"ansible-shell-command"}


def test_shell_module_is_only_a_low_confidence_hint() -> None:
    rule = RULES["ansible-shell-command"]
    assert rule.severity.value == "low" and rule.confidence == "low"


def test_playbook_end_to_end(tmp_path: Path) -> None:
    book = tmp_path / "playbooks" / "site.yml"
    book.parent.mkdir()
    book.write_text(
        "- hosts: web\n"
        "  become: true\n"
        "  vars:\n"
        '    db_password: "hunter2-prod"\n'
        '    api_key: "{{ vault_api_key }}"\n'
        "  tasks:\n"
        "    - name: install\n"
        "      ansible.builtin.shell: curl -sL https://get.example.com | bash\n"
        "    - name: repo\n"
        "      ansible.builtin.yum_repository:\n"
        "        name: app\n"
        "        baseurl: https://repo.example.com/\n"
        "        gpgcheck: no\n"
    )
    found = {(f.rule_id, f.line) for f in scan_directory(tmp_path).findings}
    assert ("ansible-hardcoded-secret", 4) in found
    assert not any(rule == "ansible-hardcoded-secret" and line == 5 for rule, line in found)
    assert ("ansible-curl-pipe-shell", 8) in found
    assert ("ansible-package-signature-off", 13) in found


def test_molecule_scenarios_count_as_tests(tmp_path: Path) -> None:
    prepare = tmp_path / "molecule" / "default" / "prepare.yml"
    prepare.parent.mkdir(parents=True)
    prepare.write_text("- hosts: all\n  tasks:\n    - yum_repository:\n        gpgcheck: false\n")
    found = [
        f for f in scan_directory(tmp_path).findings if f.rule_id == "ansible-package-signature-off"
    ]
    assert found and all(f.context == "test" for f in found)
