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
        "from transformers import AutoModel\n"
        'm = AutoModel.from_pretrained("x", trust_remote_code=True)\n'
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
        (
            "unsafe.py",
            "subprocess.run(resp.content[0].text, shell=True)",
            "ml-llm-output-subprocess-shell",
        ),
        ("unsafe.py", 'os.system(tool_args["command"])', "ml-agent-os-system-command"),
        ("unsafe.ts", "eval(response.text)", "ml-llm-output-eval-js"),
        (
            "unsafe.ts",
            "element.innerHTML = completion.choices[0].message.content;",
            "ml-llm-output-html",
        ),
        ("unsafe.ts", "element.innerHTML = response.text;", "ml-llm-output-html"),
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
        ("safe.py", "ast.literal_eval(resp.text)"),
        ("safe.ts", "el.innerHTML = other.textContent"),
        ("safe.ts", "eval(script.textContent)"),
        ("safe.py", 'cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")'),
        ("safe.py", "os.system(args[0])"),
    ],
)
def test_safe_output_handling_not_flagged(tmp_path: Path, filename: str, line: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    assert not _scan_ml(f).findings

@pytest.mark.parametrize(
    ("filename", "source", "rule_id"),
    [
        ("openai.py", "client.chat.completions.create(model=\"gpt-4o\", messages=messages)", "ml-openai-anthropic-unbounded-output"),
        ("openai.ts", "await openai.responses.create({ model, input });", "ml-openai-anthropic-unbounded-output"),
        ("anthropic.py", "client.messages.create(model=\"claude\", messages=messages)", "ml-openai-anthropic-unbounded-output"),
        ("gemini.py", "model.generate_content(prompt)", "ml-gemini-unbounded-output"),
        ("gemini.ts", "model.generate_content(prompt);", "ml-gemini-unbounded-output"),
        ("mistral.py", "client.chat.complete(model=\"mistral\", messages=messages)", "ml-mistral-unbounded-output"),
        ("litellm.py", "litellm.completion(model=model, messages=messages)", "ml-litellm-unbounded-output"),
        ("langchain.py", "llm = ChatOpenAI(model=\"gpt-4o\")", "ml-langchain-unbounded-output"),
        ("request.py", "payload = {\"model\": request.json, \"messages\": request.body}\n", "ml-llm-model-or-history-from-request"),
        ("large.py", "params = {\"max_output_tokens\": 20000}", "ml-llm-output-token-limit-too-high"),
        ("timeout.py", "client.chat.completions.create(model=\"gpt-4o\", messages=messages)", "ml-llm-request-without-timeout"),
    ],
)
def test_llm_unbounded_consumption_patterns(
    tmp_path: Path, filename: str, source: str, rule_id: str
):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert rule_id in {finding.rule_id for finding in _scan_ml(f).findings}


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("safe.py", "client.chat.completions.create(model=\"gpt-4o\", messages=messages, max_tokens=512, timeout=20)"),
        ("safe.py", "model.generate_content(prompt, generation_config={\"max_output_tokens\": 512})"),
        ("safe.py", "client.chat.complete(model=\"mistral\", messages=messages, max_tokens=512)"),
        ("safe.py", "litellm.completion(model=model, messages=messages, max_tokens=512)"),
        ("safe.py", "llm = ChatOpenAI(model=\"gpt-4o\", max_tokens=512)"),
        ("safe.ts", "const model = allowedModels[request.body.model];"),
        ("safe.py", "params = {\"max_output_tokens\": 4096}"),
    ],
)
def test_bounded_llm_requests_not_flagged(tmp_path: Path, filename: str, source: str):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert not _scan_ml(f).findings


def test_llm_route_without_rate_limit_flagged(tmp_path: Path):
    f = tmp_path / "routes.py"
    f.write_text(
        '@app.post("/chat")\n'
        "async def chat(request):\n"
        "    return await client.chat.completions.create(\n"
        '        model="gpt-4o", messages=request.json["messages"]\n'
        "    )\n"
    )
    assert "ml-llm-route-without-rate-limit" in {
        finding.rule_id for finding in _scan_ml(f).findings
    }


@pytest.mark.parametrize(
    "limiter",
    [
        '@limiter.limit("10/minute")',
        "app.add_middleware(RateLimiter)",
        "rate_limit = Limiter(key_func=get_remote_address)",
        "app.use(express_rate_limit())",
    ],
)
def test_llm_route_with_rate_limit_not_flagged(tmp_path: Path, limiter: str):
    f = tmp_path / "routes.py"
    f.write_text(
        limiter + "\n"
        '@app.post("/chat")\n'
        "async def chat(request):\n"
        "    return await client.chat.completions.create(model=\"gpt-4o\", messages=messages)\n"
    )
    assert "ml-llm-route-without-rate-limit" not in {
        finding.rule_id for finding in _scan_ml(f).findings
    }
