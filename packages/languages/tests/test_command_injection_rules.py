"""Regression tests for command-injection rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("safe.py", 'subprocess.run(["ls", path])'),
        ("safe_args.py", "subprocess.run(cmd, check=True, capture_output=True)"),
        ("safe_async.py", "asyncio.create_subprocess_exec(*cmd)"),
        ("safe_js.js", "regex.exec(input)"),
        ("safe_fs.js", "filesystem(path)"),
        ("safe_spawn.js", 'child_process.spawn("ls", [path])'),
        ("safe_java.java", "Runtime.getRuntime().exec(new String[] { command, path })"),
        ("safe_go.go", 'exec.Command("git", "status")'),
    ],
)
def test_safe_process_calls_are_not_flagged(tmp_path: Path, name: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(code)
    result = scan_directory(tmp_path)

    assert "command-injection" not in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("shell_true.py", 'subprocess.run(f"ls {path}", shell=True)'),
        ("os_system.py", 'os.system("ping " + host)'),
        ("os_popen.py", 'os.popen("cat " + filename)'),
        ("exec.js", "child_process.exec(`ls ${dir}`)"),
        ("exec_sync.js", 'child_process.execSync("cat " + filename)'),
        ("java.java", 'Runtime.getRuntime().exec("cat " + filename)'),
        ("go.go", 'exec.Command("sh", "-c", command)'),
    ],
)
def test_dynamic_shell_calls_are_flagged(tmp_path: Path, name: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(code)
    result = scan_directory(tmp_path)

    assert "command-injection" in {finding.rule_id for finding in result.findings}
