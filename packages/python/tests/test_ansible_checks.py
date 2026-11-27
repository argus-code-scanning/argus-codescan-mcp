"""Built-in Ansible task checks (no_log, debug, get_url checksum, Galaxy pinning)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.tools.ansible_checks import ansible_findings


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def found(root: Path) -> list[tuple[str, str, int]]:
    return sorted((f.rule_id, f.file, f.line) for f in ansible_findings(str(root))[0])


PLAYBOOK = """\
- hosts: db
  tasks:
    - name: Create app user
      community.mysql.mysql_user:
        name: app
        password: "{{ vault_app_password }}"
    - name: Same, hidden
      community.mysql.mysql_user:
        name: app2
        password: "{{ vault_app_password }}"
      no_log: true
    - block:
        - name: Inside a quiet block
          ansible.builtin.user:
            name: deploy
            password: "{{ deploy_hash }}"
      no_log: true
    - name: Call the API
      ansible.builtin.uri:
        url: https://api.example.com/deploy
        headers:
          Authorization: "Bearer {{ api_token }}"
    - name: Lock a system account
      ansible.builtin.user:
        name: games
        password: "*"
        update_password: on_create
    - name: Show it
      ansible.builtin.debug:
        var: db_password
    - name: Show something harmless
      ansible.builtin.debug:
        msg: "{{ app_version }}"
    - name: Download
      ansible.builtin.get_url:
        url: https://example.com/tool.tar.gz
        dest: /tmp/tool.tar.gz
    - name: Download, pinned
      ansible.builtin.get_url:
        url: https://example.com/tool.tar.gz
        dest: /tmp/tool.tar.gz
        checksum: sha256:abc123
"""


def test_playbook_tasks(tmp_path: Path) -> None:
    write(tmp_path, {"site.yml": PLAYBOOK})
    assert found(tmp_path) == [
        ("ansible-debug-secret", "site.yml", 28),
        ("ansible-get-url-no-checksum", "site.yml", 34),
        ("ansible-secret-no-log", "site.yml", 3),
        ("ansible-secret-no-log", "site.yml", 18),
    ]


def test_play_level_no_log_and_free_form_args(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "quiet.yml": "- hosts: all\n  no_log: true\n  tasks:\n"
            "    - mysql_user: name=app password={{ pw }}\n",
            "loud.yml": "- hosts: all\n  tasks:\n    - mysql_user: name=app password={{ pw }}\n",
        },
    )
    assert found(tmp_path) == [("ansible-secret-no-log", "loud.yml", 3)]


def test_role_tasks_file_and_vault_tags(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "roles/db/tasks/main.yml": "- name: user\n  postgresql_user:\n    name: app\n"
            "    password: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6162\n",
            "group_vars/all/vault.yml": "$ANSIBLE_VAULT;1.1;AES256\n616263\n",
        },
    )
    assert found(tmp_path) == [("ansible-secret-no-log", "roles/db/tasks/main.yml", 1)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("roles:\n  - name: geerlingguy.nginx\n", [("ansible-galaxy-unpinned", 2)]),
        ("roles:\n  - name: geerlingguy.nginx\n    version: 3.2.0\n", []),
        (
            "roles:\n  - src: https://github.com/acme/role.git\n    version: main\n",
            [("ansible-galaxy-unpinned", 2)],
        ),
        ("collections:\n  - name: community.general\n    version: '>=8.0.0'\n", []),
        ("collections:\n  - community.general\n", [("ansible-galaxy-unpinned", 0)]),
        ("- src: geerlingguy.java\n", [("ansible-galaxy-unpinned", 1)]),
    ],
)
def test_galaxy_requirements(tmp_path: Path, text: str, expected: list[tuple[str, int]]) -> None:
    write(tmp_path, {"requirements.yml": text})
    assert [(rule, line) for rule, _, line in found(tmp_path)] == expected


def test_branch_pins_are_medium_plain_galaxy_names_low(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "requirements.yml": "roles:\n  - name: a.b\n  - src: https://github.com/x/y.git\n    version: master\n"
        },
    )
    by_line = {f.line: f.severity.value for f in ansible_findings(str(tmp_path))[0]}
    assert by_line == {2: "low", 3: "medium"}


def test_molecule_is_test_context(tmp_path: Path) -> None:
    write(tmp_path, {"molecule/default/converge.yml": PLAYBOOK})
    findings = ansible_findings(str(tmp_path))[0]
    assert findings and all(f.context == "test" for f in findings)
    assert {f.severity.value for f in findings if f.rule_id == "ansible-secret-no-log"} == {"low"}


def test_ignores_non_ansible_yaml(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            ".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - run: echo\n",
            "docker-compose.yml": "services:\n  db:\n    environment:\n      password: x\n",
            "broken.yml": "- hosts: [\n",
        },
    )
    assert found(tmp_path) == []


@pytest.mark.asyncio
async def test_scan_ansible_runs_builtin_without_tools(tmp_path: Path) -> None:
    from argus.tools.ansible import run_all_ansible

    write(tmp_path, {"site.yml": PLAYBOOK + "    - shell: curl -s https://x.sh | bash\n"})
    results = await run_all_ansible(str(tmp_path), tools=["builtin"])
    rules = {f.rule_id for r in results for f in r.findings}
    assert {"ansible-secret-no-log", "ansible-curl-pipe-shell"} <= rules
