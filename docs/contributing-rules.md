# Add a YAML Security Rule in 5 Minutes

Most Argus built-in checks are defined as YAML files in `argus-languages`. You can add a pattern-based security rule without modifying the Python MCP server.

## Where Rules Live

Built-in rules are located in:

```text
packages/languages/src/argus_languages/bundled_rules/
```

| File            | Purpose                              |
| --------------- | ------------------------------------ |
| `malware.yaml`  | Miners, reverse shells, and droppers |
| `ml.yaml`       | AI/ML unsafe loads and LLM keys      |
| `database.yaml` | Database and ORM-related issues      |
| `common.yaml`   | Shared detection patterns            |

Existing rule packs, such as `malware.yaml`, are already registered.

If you create a new rule-pack file, register its filename in `RULE_FILES` inside:

```text
packages/languages/src/argus_languages/rules_loader.py
```

## Rule Fields

A rule typically contains the following fields:

```yaml
- id: malware-example-rule
  title: Short human-readable title
  severity: critical
  pattern: 'regex here'
  flags: [i]
  languages: [shell, python]
```

* **`id`**: A unique, kebab-case identifier.
* **`title`**: A short, descriptive title.
* **`severity`**: The risk level: `critical`, `high`, `medium`, `low`, or `info`, as supported by the project.
* **`pattern`**: A Python regular expression used to identify a potential security issue.
* **`flags`**: Optional matching flags. For example, `i` enables case-insensitive matching and `m` enables multiline mode.
* **`languages`**: An optional list of languages to which the rule applies. Omit it to use the default behavior supported by the rule loader.
* **`exclude_languages`**: Optional. Languages a rule without `languages` should skip, for example when a language-specific pack covers the case more precisely (`weak-crypto` skips `php` because `php.yaml` flags password hashing and weak ciphers instead).
* **`classification`**: Optional data classification for findings (`pii`, `phi`, `pci`, `confidential`, `public`). Defaults to `unset`.
* **`fix_guidance`**: Optional. One or two sentences telling the developer how to fix the issue; shown in reports as the finding's fix guidance. Use a YAML folded block (`>-`) for longer text.

Config file types (`composer`, `dotenv-production`, `dotenv-example`) only receive rules that list them in `languages`; rules without `languages` are not applied to them.

### Tips for Writing Good Rules

* **Keep patterns line-oriented.** Patterns are evaluated per line rather than against the entire file.
* **Prefer specific patterns.** Hostnames and recognizable API shapes are generally more useful than vague keywords.
* **Consider false positives.** If a pattern may match legitimate code, mention that limitation in the rule title or documentation.
* **Follow existing conventions.** Check neighboring rules for consistent formatting and supported fields.

## Example: Detecting Mining Pool Hostnames

The following example demonstrates a rule from the malware pack:

```yaml
- id: malware-mining-pool-hosts
  title: Known crypto mining pool hostname
  severity: critical
  pattern: 'hashvault\.pro|xmrpool\.eu|c3pool\.com'
  flags: [i]
```

This rule matches the listed hostnames without distinguishing between uppercase and lowercase letters.

## Add a Test

Create or extend a test file under:

```text
packages/languages/tests/
```

For example:

```python
from pathlib import Path

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def test_mining_pool_hosts(tmp_path: Path):
    f = tmp_path / "pool.sh"
    f.write_text('url = "https://xmrpool.eu:3333"\n')

    result = scan_path(
        f,
        rules=load_rules_from_files(("malware.yaml",)),
    )

    assert "malware-mining-pool-hosts" in {
        x.rule_id for x in result.findings
    }
```

This test creates a temporary file containing a mining pool hostname, scans it, and checks whether the expected rule ID appears in the results.

Use a file extension recognized by the scanner, such as `.sh`, `.py`, `.ps1`, `.bat`, or `.php`.

Follow the existing test conventions and verify that the imports and scanner APIs match the current implementation.

## Run Tests Locally

The following commands show the expected development workflow on Linux or macOS:

```bash
cd packages/python

python3 -m venv .venv
source .venv/bin/activate

pip install -e ../languages -e ".[dev]"

pytest ../languages/tests/test_malware_rules.py -q
```

To run all language tests:

```bash
pytest ../languages/tests -q
```

If you are using Windows PowerShell, activate the virtual environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

Run the commands from the appropriate directories and use the test paths that actually exist in the repository.

## Try the Rule with the CLI

To scan a sample for malware indicators:

```bash
argus scan malware /path/to/sample
```

To scan using the built-in code rules:

```bash
argus scan code /path/to/sample
```

Replace `/path/to/sample` with the path to your test file. Ensure the CLI is installed and that these commands match the project's current CLI interface.

## Open a Pull Request

1. Fork the repository and create a branch from `main`, or from `dev` if the project maintainers require it.
2. Add the YAML rule and its corresponding test.
3. Run the relevant tests and review your changes.
4. Open a pull request explaining the rule ID, the security issue it detects, and why it is useful.
5. Link the related issue when applicable, using a reference such as `Fixes #66`.

Find suitable beginner-friendly issues here:

[Good first issues](https://github.com/argus-code-scanning/argus-codescan-mcp/labels/good%20first%20issue)

## Additional Resources

* [Contributing Guide](../CONTRIBUTING.md)
* [Architecture Guide](architecture.md)

Thank you for helping improve Argus CodeScan MCP!

