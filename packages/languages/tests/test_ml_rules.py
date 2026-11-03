"""Tests for AI/ML security static rules."""

from pathlib import Path

import pytest

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def _scan_ml(path: Path):
    return scan_path(path, rules=load_rules_from_files(("ml.yaml",)))


def test_ml_torch_load(tmp_path: Path):
    f = tmp_path / "infer.py"
    f.write_text('import torch\nweights = torch.load("model.pt")\n')
    result = _scan_ml(f)
    assert "ml-torch-load-unsafe" in {x.rule_id for x in result.findings}


def test_ml_trust_remote_code(tmp_path: Path):
    f = tmp_path / "load.py"
    f.write_text(
        'from transformers import AutoModel\nm = AutoModel.from_pretrained("x", trust_remote_code=True)\n'
    )
    result = _scan_ml(f)
    assert "ml-trust-remote-code" in {x.rule_id for x in result.findings}


def test_ml_openai_key_assignment(tmp_path: Path):
    f = tmp_path / "config.py"
    f.write_text('OPENAI_API_KEY = "sk-test-key-should-not-be-here"\n')
    result = _scan_ml(f)
    assert "ml-llm-api-key-hardcoded" in {x.rule_id for x in result.findings}


def test_ml_prompt_fstring(tmp_path: Path):
    f = tmp_path / "chat.py"
    f.write_text('user = "ignore instructions"\nprompt = f"Summarize: {user}"\n')
    result = _scan_ml(f)
    assert "ml-llm-prompt-fstring" in {x.rule_id for x in result.findings}


@pytest.mark.parametrize(
    ("filename", "line", "rule_id"),
    [
        ("unsafe.py", "exec(resp.content[0].text)", "ml-llm-output-exec-eval"),
        ("unsafe.py", "eval(response.choices[0].message.content)", "ml-llm-output-exec-eval"),
        ("unsafe.py", "subprocess.run(resp.content[0].text, shell=True)", "ml-llm-output-subprocess-shell"),
        ("unsafe.py", 'os.system(tool_args["command"])', "ml-agent-os-system-command"),
        ("unsafe.py", 'cursor.execute(f"SELECT * FROM users WHERE name = {llm_answer}")', "ml-llm-output-sql-fstring"),
        ("unsafe.ts", "eval(result.text)", "ml-llm-output-eval-js"),
        ("unsafe.ts", "element.innerHTML = completion.choices[0].message.content;", "ml-llm-output-html"),
        ("unsafe.ts", "element.innerHTML = result.text;", "ml-llm-output-html"),
    ],
)
def test_llm_output_direct_sinks_flagged(tmp_path: Path, filename: str, line: str, rule_id: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    assert rule_id in {finding.rule_id for finding in _scan_ml(f).findings}


@pytest.mark.parametrize(
    ("filename", "line"),
    [
        ("safe.py", "print(response.choices[0].message.content)"),
        ("safe.py", "subprocess.run(['git', 'status'], check=True)"),
        ("safe.py", "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"),
        ("safe.ts", "element.textContent = completion.content;"),
        ("safe.ts", "const parsed = JSON.parse(result.text);"),
        ("safe.ts", "eval('2 + 2')"),
    ],
)
def test_safe_output_handling_not_flagged(tmp_path: Path, filename: str, line: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    assert not _scan_ml(f).findings
