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
        ("safe_exec_file.js", 'child_process.execFile("ls", [path])'),
        ("safe_java.java", "Runtime.getRuntime().exec(new String[] { command, path })"),
        ("safe_process_builder.java", 'new ProcessBuilder("git", "status")'),
        ("safe_go.go", 'exec.Command("git", "status")'),
        ("safe_subprocess.py", 'subprocess.run("ls", shell=False)'),
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
        ("os_system_variable.py", "os.system(cmd)"),
        ("os_system_format.py", 'os.system("ls {}".format(directory))'),
        ("os_popen.py", 'os.popen("cat " + filename)'),
        ("exec.js", "child_process.exec(`ls ${dir}`)"),
        ("cp_exec.js", 'cp.exec("ls " + directory)'),
        ("destructured_exec.js", "exec('ls ' + directory)"),
        ("exec_sync.js", 'child_process.execSync("cat " + filename)'),
        ("exec_sync_template.js", "execSync(`rm ${file}`)"),
        ("java_variable.java", "Runtime.getRuntime().exec(cmd)"),
        ("process_builder.java", 'new ProcessBuilder("sh", "-c", cmd)'),
        ("java.java", 'Runtime.getRuntime().exec("cat " + filename)'),
        ("go.go", 'exec.Command("sh", "-c", "ls " + directory)'),
        ("subprocess_nested.py", "subprocess.run(build(cmd), shell=True)"),
        ("popen_multiline.py", "subprocess.Popen(\n    cmd,\n    shell=True,\n)"),
        ("ruby.rb", 'system("ls #{directory}")'),
        ("ruby_backtick.rb", "`ls #{directory}`"),
        ("ruby_percent_x.rb", "%x(ls #{directory})"),
        ("csharp.cs", 'Process.Start("cmd.exe", "/c " + argument)'),
        ("perl.pl", 'system("ls $directory")'),
        ("shell.sh", 'bash -c "$COMMAND"'),
    ],
)
def test_dynamic_shell_calls_are_flagged(tmp_path: Path, name: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(code)
    result = scan_directory(tmp_path)

    assert "command-injection" in {finding.rule_id for finding in result.findings}
