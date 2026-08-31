"""Tests for IaC scanner Ansible auto-detection."""

from pathlib import Path

from argus.tools.iac import _looks_like_ansible_project


def test_generic_yaml_does_not_trigger_ansible(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflows").mkdir()
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: push\n")
    assert _looks_like_ansible_project(tmp_path) is False


def test_ansible_roles_dir_triggers_ansible(tmp_path: Path):
    (tmp_path / "roles").mkdir()
    assert _looks_like_ansible_project(tmp_path) is True


def test_playbook_yaml_triggers_ansible(tmp_path: Path):
    (tmp_path / "site.yml").write_text(
        "---\n- hosts: all\n  become: true\n  tasks:\n    - name: ping\n      ansible.builtin.ping:\n"
    )
    assert _looks_like_ansible_project(tmp_path) is True


def test_single_playbook_file(tmp_path: Path):
    playbook = tmp_path / "deploy.yaml"
    playbook.write_text("- hosts: webservers\n  tasks: []\n")
    assert _looks_like_ansible_project(playbook) is True
