# Features Roadmap

## Implemented — AI/ML & LLM pipeline scanning

| Item | Location |
|------|----------|
| Rule pack | `packages/languages/.../bundled_rules/ml.yaml` |
| Scanner | `packages/python/src/argus/tools/ml.py` |
| CLI | `argus scan ml .` |
| MCP tool | `scan_ml` |

**Rules include:** unsafe `torch.load` / joblib / dill, Hugging Face `trust_remote_code`, hardcoded LLM API keys, f-string prompts, LangChain user input in templates, Gradio `share=True`, model paths from request input.

```bash
argus scan ml ./my-ml-app
```

Included in `argus scan all` and MCP `scan_all`.

---

## Planned — AI/ML (next)

| Feature | Status |
|---------|--------|
| Model artifact scanning (ONNX, safetensors metadata) | Planned |
| LLM dependency CVE checks (langchain, transformers, etc.) | Planned |
| Prompt-injection DAST for chat endpoints | Planned |
| Ollama / vLLM serving config checks | Planned |
