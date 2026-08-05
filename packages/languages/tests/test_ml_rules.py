"""Tests for AI/ML security static rules."""

from pathlib import Path

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
