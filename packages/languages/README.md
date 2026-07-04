# argus-languages

Built-in security pattern scanner for **all major languages and IaC** — pure Python, no external tools.

Install on its own or as part of `argus-scan`:

```bash
pip install argus-languages
argus-languages scan /path/to/project
```

Or via the full Argus CLI:

```bash
pip install argus-scan
argus scan code /path/to/project
```

## Supported languages

| Category | Languages / formats |
|----------|---------------------|
| **Web & app** | JavaScript, TypeScript, Python, Java, Kotlin, PHP, Go, Ruby, C#, Rust, Swift, Scala, Perl, Lua, Elixir, Vue |
| **Infrastructure** | Terraform (`.tf`, `.hcl`), Ansible playbooks, Docker, Kubernetes manifests |
| **Shell & SQL** | Bash/Shell scripts, SQL |

Rules live in `src/argus_languages/bundled_rules/` as YAML so they can be shared across Python (and other packages later).

## Usage

```python
from argus_languages import scan_directory

result = scan_directory("/path/to/repo")
for finding in result.findings:
    print(finding.file, finding.line, finding.title)
```

## npm vs Python

- **`packages/npm`** — Node.js only (JS/TS SCA + eslint-security)
- **`packages/languages`** — all other languages (install via pip)
- **`packages/python`** — full Argus CLI/MCP; depends on `argus-languages`
