# Contributing to argus-scan

Thank you for helping make security tooling more accessible! Contributions of all kinds are welcome: new scanners, bug fixes, documentation, new language clients, and more.

---

## Ways to Contribute

| Type | Examples |
|------|---------|
| **New scanner** | Add support for a new SAST/DAST/SCA/secret/IaC tool |
| **New language client** | Rust, Java/Maven, Ruby gem, .NET NuGet package |
| **Bug fix** | Fix a parsing issue, incorrect severity mapping, crash |
| **Docs** | Improve setup guides, add examples, fix typos |
| **Tests** | Add test cases for edge cases or new tools |
| **CI/CD** | Improve GitHub Actions workflows |

---

## Development Setup

### Python core

```bash
git clone https://github.com/GabrielOkiri/argus-mcp
cd argus-scan/packages/python

python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src tests
mypy src
```

### npm package

```bash
cd packages/npm
npm install
npm run build
npm test
```

### VS Code extension

```bash
cd extensions/vscode
npm install
npm run build
# Press F5 in VS Code to open the Extension Development Host
```

### Go CLI

```bash
cd packages/go
go build ./cmd/argus-scan
go test ./...
```

---

## Adding a New Scanner

1. **Add the runner** in `packages/python/src/argus/tools/<category>.py`:

   ```python
   async def run_mytool(target: str, timeout: int = 120) -> ScanResult:
       result = ScanResult(tool="mytool", scan_type=ScanType.SAST, target=target)

       if not is_tool_available("mytool"):
           result.tool_available = False
           result.errors.append("mytool not installed. Install with: pip install mytool")
           return result

       cmd = ["mytool", "--json", "--", target]
       code, stdout, stderr = await run_command(cmd, timeout=timeout)
       result.raw_output = stdout

       data = parse_json_output(stdout)
       if not data:
           if stderr:
               result.errors.append(stderr[:400])
           return result

       for item in data.get("results", []):
           finding = Finding(
               title=item.get("rule_id", "mytool-finding"),
               severity=map_severity(item.get("severity", "medium")),
               scan_type=ScanType.SAST,
               tool="mytool",
               file=item.get("file", ""),
               line=item.get("line", 0),
               description=item.get("message", ""),
           )
           result.findings.append(finding)

       return result
   ```

2. **Register in `server.py`**:
   - Add `types.Tool(...)` to `list_tools()` with a description and `inputSchema`
   - Add a handler case in `call_tool()`
   - Add to `TOOLS_REGISTRY` for `check_tools` output

3. **Add tests** in `packages/python/tests/test_<category>.py`:
   - Test tool-not-installed path (mock `is_tool_available` → `False`)
   - Test output parsing with a sample JSON fixture
   - Test error handling

4. **Update docs**:
   - `docs/tool-setup.md` — install instructions and description
   - `docs/api-reference.md` — if it adds a new MCP tool or parameter
   - `README.md` — add to the tools table

---

## Pull Request Process

1. Fork the repository and create a branch:
   ```bash
   git checkout -b feat/add-grype-scanner
   ```

2. Make your changes following the guidelines below.

3. Run the test suite and linters:
   ```bash
   cd packages/python && pytest && ruff check src tests
   ```

4. Push and open a PR against `main`. Fill out the PR template.

5. A maintainer will review within a few days.

---

## Code Style

### Python

- **Formatter:** ruff format (PEP 8, 100-char line length)
- **Linter:** ruff (E, F, W, I, UP rules)
- **Type hints:** required for all public functions
- **Docstrings:** module-level and function-level for new public APIs
- **No comments** that just narrate the code — only explain *why*, not *what*

### TypeScript

- **Strict mode** enabled
- **ESLint** for linting
- Prefer `async/await` over raw Promises

### Go

- `gofmt` formatted
- `golangci-lint` passing

---

## Commit Message Convention

```
<type>(<scope>): <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`

Examples:
```
feat(sast): add Grype SCA scanner
fix(sca): handle Safety v3 JSON format change
docs(api): document scan_iac framework parameter
test(secrets): add TruffleHog output parsing tests
```

---

## Reporting Issues

Use the GitHub issue templates:
- 🐛 **Bug report** — unexpected behaviour, crashes, wrong results
- 🔒 **Security vulnerability** — see [SECURITY.md](SECURITY.md) instead of public issues
- 💡 **Feature request** — new scanner, new client language, new option
- 📖 **Documentation** — missing or incorrect docs

---

## Licence

By contributing, you agree that your contributions will be licensed under the [MIT Licence](LICENSE).
