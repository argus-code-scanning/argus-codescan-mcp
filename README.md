# Argus

> *In Greek mythology, Argus Panoptes was the hundred-eyed giant — an all-seeing guardian who never slept.*

**One open-source scanner. Many eyes. SAST, SCA, secrets, IaC, Terraform, Ansible — CLI, MCP, and GitHub SARIF.**

Argus orchestrates **20+ industry-standard tools** (Semgrep, Trivy, Gitleaks, tfsec, Checkov, OWASP ZAP, and more) behind a single command and an **MCP server** for any MCP-compatible IDE or AI client. Runs locally. **No Argus subscription.** MIT licensed.

[![Python CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-python.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-python.yml)
[![npm CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-npm.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-npm.yml)
[![Go CI](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-go.yml/badge.svg)](https://github.com/argus-code-scanning/argus-codescan-mcp/actions/workflows/ci-go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Install:** `pip install argus-scan` · `npm install -D argus-codescan` · [Docker](packages/docker/README.md) · [Launch kit](docs/launch/show-hn.md)

---

## Why Argus?

| | Run scanners yourself | Argus |
|---|----------------------|--------|
| **Setup** | Install & configure each tool separately | One CLI / MCP config |
| **Output** | Different JSON/text per tool | Unified report + SARIF |
| **CI** | Wire scripts yourself | `--format sarif`, `.argus.yml`, baseline diff |
| **AI (MCP IDE)** | Manual copy-paste | MCP tools: `scan_all`, `compare_scans`, `apply_fix` |
| **Cost** | Free (DIY labor) | Free (MIT) — AI client optional |
| **Fixes** | You decide | Scan never auto-fixes; fix only when you ask |

**Good for:** solo devs, OSS maintainers, teams wanting DevSecOps without a proprietary scanner SaaS.

**Not a replacement for:** managed AppSec platforms with centralized policy, SOC, or compliance sign-off — Argus is a **local orchestrator** you own.

---

## Two ways to use Argus

### 1 — Standalone CLI (no AI needed)

```bash
argus scan sast /my/project
argus scan terraform /my/infra
argus scan all /my/project --fail-on high
argus scan code /my/project --format sarif -o argus.sarif
argus scan ml /my/ml-app
argus scan malware /my/project
argus review .                      # local code review — git-changed files only
argus review . --staged             # only staged files
argus review . --base main          # vs main (+ local dirty files)
argus compare baseline.json current.json --fail-on-new
argus tools
```

Works for anyone. Just install Argus and the open-source scanner tools.

### 2 — MCP server (AI-assisted, optional)

```bash
argus mcp    # starts the MCP server
```

Connect Cursor, VS Code, Claude Desktop, JetBrains, Windsurf, or any MCP-compatible IDE and drive scans through natural language. The AI subscription is for the AI client — Argus itself is always free.

---

## What Argus Scans

| Category | Tools |
|----------|-------|
| **SAST** | Semgrep · Bandit · ESLint-security · flake8-bandit |
| **DAST** | OWASP ZAP · Nikto |
| **SCA** | Trivy · Safety · pip-audit · npm audit · govulncheck · composer audit · built-in OSV check for every lockfile (npm, Python, Go, Flutter/Dart, Rust, Ruby, .NET, PHP, Maven/Gradle) · built-in OSV known-malicious package check (MAL- records) |
| **Secrets** | Gitleaks · detect-secrets · TruffleHog |
| **IaC** | Checkov · Trivy config · Terrascan · KICS |
| **Terraform** | tfsec · tflint · terraform validate · KICS · Checkov |
| **Ansible** | ansible-lint · KICS · Checkov |
| **Container** | Trivy image scan |
| **AI/ML** | Built-in rules — unsafe model load, LLM API keys, prompt injection, Gradio share |
| **Malware** | Built-in heuristics — crypto miners, reverse shells, BAT/PS1 droppers, web shells (not AV) |

### Shell, PowerShell and batch scripts

`scan code` / `scan sast` (both packages) check `.sh` `.bash` `.zsh`, `.ps1` `.psm1` `.psd1` and `.bat` `.cmd` files, plus extensionless scripts found by their `#!` line (`bin/deploy`, `scripts/setup`). `bin/` is scanned unless it holds build output (`Debug/`, `Release/`, `.dll`).

| Shell | PowerShell | Batch |
|---|---|---|
| `eval "$1"` / `eval $CMD` | `Invoke-Expression $var`, `$x \| iex` | `net user … /add`, admin group adds |
| `rm -rf "$DIR/"` without `${DIR:?}` | `-ExecutionPolicy Bypass` | `net use … /user:x Password`, `runas /savecred`, `set PASSWORD=…` |
| `curl -k`, `wget --no-check-certificate`, `git http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | plaintext `ConvertTo-SecureString "…" -AsPlainText`, `$password = "…"` | `netsh advfirewall … state off` |
| `chmod 777` / `o+w` | `ServerCertificateValidationCallback = {$true}`, `-SkipCertificateCheck` | |
| `sshpass -p`, `mysql -pSecret`, `export DB_PASSWORD=literal` | SSL3 / TLS 1.0 / 1.1 | |
| fixed `/tmp/…` files (low confidence), `NOPASSWD: ALL`, `StrictHostKeyChecking=no` | | |

Download-and-run (`curl … \| sh`, `iwr … \| iex`), encoded commands, certutil/bitsadmin downloads and Defender tampering are reported by the malware rules.

### Vulnerable dependencies in every language

`argus scan sca` (Python) and `npx argus-codescan scan sca` (npm) check the exact versions in your lockfiles against [OSV](https://osv.dev), with nothing else to install:

| Ecosystem | Files read |
|---|---|
| JavaScript / TypeScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| Go | `go.mod` (and the Go toolchain from its `toolchain` line) |
| Dart / Flutter | `pubspec.lock` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| .NET | `packages.lock.json` |
| PHP | `composer.lock` |
| Java / Kotlin | `pom.xml`, Gradle lockfiles, build files and version catalogs |

There is **one finding per package**, with every advisory for that version, the version that fixes all of them, how the package gets into your project (`via chrono › time`), and the command for that ecosystem (`cargo update -p time --precise 0.2.23`, `go get …`, `flutter pub upgrade …`). Dev-only packages are lowered one level. When an ecosystem's own tool is installed (npm audit, pip-audit, govulncheck, composer audit, or Trivy for all of them), that tool covers it instead, so nothing is reported twice. Only package names and versions are sent to OSV; `--no-network` (or `ARGUS_NO_NETWORK=1`) skips the check. In the npm package, `package-lock.json` stays with npm audit and every other lockfile goes to OSV.

#### npm details


`scan sca` runs `npm audit` for every lockfile and reports **one finding per advisory**, with:

- the installed version (`picomatch@4.0.7`) and **how it gets into your project**, runtime paths first: `via typeorm › tinyglobby › picomatch, vitest › picomatch`
- **fix advice** that won't break you: when npm's only "fix" is to downgrade one of your dependencies (`npm audit fix --force` moving `typeorm` 1.1.1 to 0.3.31), Argus says there is no safe fix yet instead
- dev-only packages lowered one severity level and marked `dev dependency`
- a note when `npm audit` shows a bigger number: it counts every package that *depends on* a vulnerable one, so 4 advisories can show up as "22 vulnerabilities"

```
HIGH     picomatch@4.0.7            picomatch vulnerable to ReDoS through sing
         via typeorm › tinyglobby › picomatch, vitest › picomatch
         fix: No safe fix yet: npm audit fix --force would downgrade typeorm 1.1.1 to 0.3.31. ...
```

### Known-malicious dependencies

`argus scan sca` (and `scan all`, and the MCP `scan_sca` tool) also checks every package in your lockfiles against OSV's **known-malicious** records (`MAL-…`, from the OpenSSF malicious-packages feed). A match is always **critical**: it means the exact version you lock was published as malware.

- Reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, pinned `requirements*.txt` (`name==version`), `composer.lock`, and for Java/Kotlin `pom.xml`, `gradle.lockfile`, `build.gradle(.kts)` and `libs.versions.toml`. Nothing is installed or run.
- Sends only package names and exact versions to `api.osv.dev`. Offline, the check is skipped with a note. To turn it off, use `--no-network` or `ARGUS_NO_NETWORK=1`.

### Typosquats and hallucinated packages

`argus scan sca` checks every direct dependency name in `package.json`, `requirements*.txt` and `pyproject.toml`:

- **Lookalikes (offline, always on):** names one character away from a top npm / PyPI package (`reqeusts`, `loadsh`, `electorn`), separator swaps (`crossenv`), added `py`/`js`/`node-`/`python-` affixes, and look-alike characters. Packages that are themselves established (in the bundled top ~15,000 lists per registry) are never reported.
- **Missing or brand-new packages (online, opt-in):** with `--registry-check`, dependencies that **don't exist** on npm / PyPI (often names an AI assistant made up, which attackers then register: "slopsquatting") are high, and packages first published in the last 30 days get a review. Projects using a private registry or `--extra-index-url` are skipped.

The popular-package lists come from [top-pypi-packages](https://hugovk.dev/top-pypi-packages/) and [npm-high-impact](https://github.com/wooorm/npm-high-impact); refresh them with `python packages/python/scripts/refresh_top_packages.py`.

### Java / Kotlin dependencies without Trivy

When Trivy isn't installed, `argus scan sca` still checks Maven and Gradle dependencies for known vulnerabilities. It reads the same files listed above and looks up exact versions on OSV. Findings include the CVE and GHSA ids, the severity and the nearest fixed version. Only literal versions are used: `${property}` values are resolved from the pom, while ranges, `1.+` and SNAPSHOTs are skipped. Nothing is downloaded, and no JVM or build is needed. With Trivy installed, Trivy covers this instead, so CVEs aren't reported twice.

### Missing rate limiting and login lockout

`argus scan sast` (and `scan all`) checks whether your API protects its sensitive endpoints against brute force and abuse. That is a **missing** control, so Argus looks at the whole project:

1. It finds login, token, password-reset, OTP/2FA, register and verify routes in Express, NestJS, Fastify, Flask, FastAPI, Django, aiohttp, Spring, JAX-RS, Ktor, Laravel, Symfony, Slim, Rails, Sinatra, Go (net/http, gin, echo, chi, Fiber), ASP.NET Core, Rust (actix, axum) and Phoenix.
2. It looks for a rate limiter (express-rate-limit, `@nestjs/throttler`, Flask-Limiter, slowapi, DRF throttling, Bucket4j, Resilience4j, Ktor RateLimit, Laravel `throttle`, Symfony RateLimiter, Rack::Attack, `x/time/rate`, `AddRateLimiter`, governor, Hammer, or your own `RateLimit` guard) and for account lockout (failed-attempt counters, `locked_until`, django-axes, `ThrottlesLogins`, Identity `lockoutOnFailure`).

| Finding | When |
|---|---|
| `api-rate-limit-missing` (medium) | Sensitive endpoints and no rate limiter anywhere |
| `auth-lockout-missing` (medium) | Login endpoints with neither rate limiting nor lockout |
| `auth-lockout-missing` (low, review) | Login is rate limited, but there is no per-account lockout |
| `api-rate-limit-missing-general` (low, review) | An HTTP API with no rate limiting at all |

Tests, docs and examples are ignored. Login delegated to an identity provider (Auth0, Cognito, Keycloak, Okta, Clerk, Firebase…) skips the lockout finding.

### Known threats (IOCs)

`argus scan threats` matches your repository against **known indicators of compromise**: malware URLs, C2 domains and IPs, and file hashes. It's also part of `argus scan malware` and `scan all`. A match is **critical**.

- **Your own list:** put one URL, domain, IPv4 or SHA-256 per line in `.argus/iocs.txt` (or point `ARGUS_IOC_FILE` at a file). This works offline, with no account.
- **abuse.ch feeds** (ThreatFox, URLhaus, MalwareBazaar): get a free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch/) and set `ARGUS_ABUSECH_AUTH_KEY`. Feeds are cached for 24 hours in `~/.cache/argus/threat-intel`; `--no-network` uses only the cache.
- Matching is local: repository content is never uploaded. Big shared platforms (GitHub, Google Drive, Discord CDN…) only match an exact listed URL, never the whole domain.

### Poisoned AI agent rules files

`argus scan malware` (and `scan code` / `scan all`) reads the files AI coding agents follow without showing them to you: `.cursorrules`, `.cursor/rules/*.mdc`, `AGENTS.md`, `CLAUDE.md`, `.claude/**/*.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.github/instructions/`, `.github/prompts/`, `.windsurfrules`, `.clinerules`, `.continue/`. It flags the "Rules File Backdoor" tricks:

- invisible or bidi Unicode (hidden text the user can't see)
- "ignore previous instructions", and hiding actions from the user ("don't tell the user…", "silently add…")
- raw-IP, paste-site, tunnel and webhook URLs; download-and-run instructions
- instructions to send or embed secrets, or to turn off TLS / auth / CSRF checks
- hidden `<!-- … -->` comments that carry instructions for the agent

Like the malware rules, these can't be silenced with `argus-ignore` and aren't downgraded in test folders: a poisoned rules file is attacker-controlled.

### Invisible Unicode and Trojan Source

`argus scan malware` (and `scan all`) also reads every source file and Markdown file for characters an editor or a diff doesn't show:

- bidi controls (Trojan Source, CVE-2021-42574): high
- zero-width characters: medium
- variation selectors and tag characters outside an emoji (GlassWorm, ASCII smuggling): high in code, medium in Markdown
- runs of 10 or more private-use characters: high

Each finding names the code point and its column, for example `U+202E RIGHT-TO-LEFT OVERRIDE at col 14`. A byte order mark at the start of a file, emoji sequences, right-to-left text, and the joiners that Persian, Hindi and other scripts are spelled with are not flagged. AI agent rules files are covered by the rule above.

## MCP Tools (for AI clients)

| Tool | What It Does |
|------|-------------|
| `scan_sast` | Static code analysis — all languages |
| `scan_dast` | Dynamic scan of a running web app |
| `scan_sca` | Vulnerable dependency detection |
| `scan_secrets` | Leaked API keys, tokens, passwords |
| `scan_iac` | Terraform, K8s, Dockerfile, Helm, Ansible misconfigs |
| `scan_terraform` | Deep Terraform scan (tfsec, tflint, validate, KICS) |
| `scan_ansible` | Ansible playbook & role security scan |
| `scan_ml` | AI/ML & LLM pipeline security (model load, API keys, prompts) |
| `scan_malware` | Malware / backdoor / crypto-miner / malicious BAT-PS1 heuristics |
| `scan_pci` | PCI-DSS cardholder-data heuristics (CVV storage, PANs in logs, hardcoded card numbers with a Luhn check, http:// card data) |
| `scan_pii` | Personal data: real-looking emails, phones, SSN / UK NI numbers, names and addresses hardcoded in code, config and fixtures (JSON/YAML/CSV/.env/SQL), PII in logs, Luhn-valid card numbers. CLI: `argus scan pii .` |
| `scan_privacy` | GDPR/CCPA code patterns: trackers without a consent mechanism, no data deletion/export, no retention field, PII in logs, fingerprinting, non-EU storage. Not a legal assessment ([docs](docs/privacy-scanning.md)). CLI: `argus scan privacy .` |
| `scan_container` | Container image CVE scanning |
| `scan_all` | Everything, in parallel |
| `review_code` | Local code review — secrets + SAST + malware on git-changed / staged files only |
| `apply_fix` | Preview or apply a fix for one finding (user must ask — scans never auto-fix) |
| `compare_scans` | Diff baseline vs current scan JSON (new/fixed findings) |
| `explain_finding` | Explain a supplied finding with CWE links, remediation guidance and a review prompt. |
| `get_scan_report` | Reformat a previous scan JSON as Markdown or SARIF |
| `get_fix_plan` | Group scan findings into a read-only remediation plan ordered by severity. |
| `check_tools` | List which scanners are installed |

MCP clients can also read the finding schema, scan categories and example workflows through the [documentation resources](docs/api-reference.md#documentation-resources).

Scans are **read-only**. Fixes run only when you ask — via `apply_fix`, VS Code Quick Fix, or your AI editing code from `fix_guidance`.

---

## Fix on request

Argus **never modifies your code during a scan**. After results come back:

| How | AI token needed? |
|-----|:----------------:|
| **VS Code Quick Fix** (lightbulb → Show fix guidance / Apply automated fix) | No |
| **MCP `apply_fix`** with `apply=true` (ESLint / Semgrep autofix only) | Only if AI calls it for you |
| **AI edits code** from finding guidance (secrets, CVEs, IaC, OWASP, etc.) | Yes (for the AI client) |

```bash
# CLI and MCP scans — detect only
argus scan all /path/to/project

# MCP: user asks AI to fix a specific finding
# → apply_fix { target, file, tool, apply: true }
```

Details: [API Reference — apply_fix](docs/api-reference.md#apply_fix)

---

## GitHub Action

One step runs Argus, fails the job at your threshold, writes a job summary and uploads SARIF to the Security tab:

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload

jobs:
  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: argus-code-scanning/argus-codescan-mcp@v1
        with:
          fail-on: high      # critical | high | medium | low | never
          scan-type: all     # all | sast | code | secrets | sca | iac | ml | malware | pci
          version: 0.10.1    # pin argus-scan for reproducible builds (empty = latest)
```

| Input | Default | |
|---|---|---|
| `scan-type` | `all` | What to scan |
| `target` | `.` | Path to scan |
| `fail-on` | `high` | Fail the job at this severity or above (`never` to only report) |
| `version` | latest | `argus-scan` version to install |
| `upload-sarif` | `true` | Upload to code scanning (skipped for fork pull requests) |
| `category` | `argus` | Code scanning category, to keep several Argus runs apart |
| `python-version` | `3.12` | Python used to run Argus |

Outputs: `sarif-file`, `findings` (count) and `failed` (`true` when findings reached `fail-on`). For supply-chain safety, pin the action to a commit SHA (`argus-code-scanning/argus-codescan-mcp@<sha> # v1`); `apply_fix` can do this for you.

## SARIF, policy & baseline diff

Ship security findings to GitHub Code Scanning, enforce repo policy, and fail CI only on **new** findings.

### SARIF export (GitHub Security tab)

```bash
# Export SARIF for GitHub Code Scanning
argus scan code . --format sarif -o argus.sarif --fail-on high

# MCP: scan_sast / scan_all with format: "sarif"
```

Upload in GitHub Actions (see `.github/workflows/argus-sarif.yml`). Pull requests scan only the files changed in the diff, and fall back to a full scan when more than 50 files changed:

```bash
argus ci pr-paths --base "$BASE_SHA" --limit 50 -o scan-paths.txt
argus scan sast . --paths-file scan-paths.txt --format sarif -o sast.sarif
argus scan secrets . --paths-file scan-paths.txt --format sarif -o secrets.sarif
```

```yaml
- run: pip install argus-scan && argus scan code . --format sarif -o argus.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: argus.sarif
    category: argus
```

### `.argus.yml` policy file

Copy [`.argus.yml.example`](.argus.yml.example) to `.argus.yml` in your repo root:

```yaml
fail_on: high
exclude_paths:
  - "tests/fixtures/**"
semgrep:
  config: p/owasp-top-ten
suppressions:
  - rule_id: bandit.B101
    path: "tests/**"
    reason: "asserts in tests"
    expires: "2026-12-31"
```

#### Accepted risks (audit gate with an expiry)

When a finding can't be fixed yet (for example, no patched version exists), accept it for a limited time instead of turning the gate off:

```yaml
accepted_risks:
  - id: GHSA-fc5q-39xc-vjpf        # advisory, CVE or rule id
    package: picomatch             # optional
    reason: "No patched version; reached via typeorm > tinyglobby"
    expires: "2026-12-17"          # required
```

The finding stays in the report (`accepted risk until 2026-12-17`) but doesn't fail `--fail-on`. Every other finding still does. Argus prints a note when an acceptance expires within 14 days, when it has expired (the finding fails again), when an entry has no `expires`, and when an entry no longer matches anything (it can be removed). This replaces hand-written `npm audit | jq` allow-list scripts, and works for every scanner and ecosystem, in both `argus` and `npx argus-codescan` (which now reads `.argus.yml` too; `--policy <file>` to choose one).

#### Personal data in scan output (`data_policy`)

Findings can quote code, and code can hold personal data. Argus masks emails, phone numbers, US SSNs, UK NI numbers and Luhn-valid card numbers (`[REDACTED:EMAIL]`) **wherever output leaves your machine**: SARIF, MCP responses to AI clients, and the cloud upload. Terminal and local JSON output keep the details you need to reproduce a finding. File, line, rule and severity are never changed, so SARIF locations and baselines keep working.

```yaml
data_policy:
  redact_pii: auto           # auto (default) | true (everywhere) | false (nowhere but the cloud upload)
  max_snippet_lines: 5       # cut long code excerpts / tool output in findings
  exclude_fields:            # drop these from every finding in the output
    - fix_guidance
```

`--redact-pii` / `--no-redact-pii` override it for one run. Set `ARGUS_REDACTION_KEY` (a secret) to get stable tags such as `[REDACTED:EMAIL:1a2b3c4d]` (an HMAC), so the same value can be matched across runs without revealing it; without a key there's no hash, because a plain hash of an SSN or phone number can be reversed by trying them all. Argus keeps no scan reports on disk: temp files are deleted after each run, and `--output` writes only where you tell it.

Argus auto-discovers `.argus.yml` when scanning. Override with `--policy path/to/.argus.yml`.

### Cutting false positives

The built-in rule packs match code line by line, so some matches are not real issues. Argus reduces the noise in three ways:

- **Ignore one finding in the code.** Put `argus-ignore` in a comment on the line, or on the line just above it. A reason is required. Without one, the finding stays and says why.

  ```python
  conn.execute(text(QUERY))  # argus-ignore[python-sql-string-build]: QUERY is a module constant
  # argus-ignore: placeholder, replaced at deploy time
  password = "changeme"
  ```

  `argus-ignore[rule-a, rule-b]: reason` covers only those rules; `argus-ignore: reason` covers every rule on that line. Suppressed findings are listed in the report metadata (`suppressed`, `suppressed_count`). For whole files or folders, use `suppressions` in `.argus.yml`.
- **Tests, docs and generated files count less.** Findings under `tests/`, `__tests__/`, `fixtures/`, `testdata/`, `docs/`, `examples/` and the like, in test files (`test_*.py`, `*_test.go`, `*.spec.ts`, `*Test.java`, …) and in minified bundles (`*.min.js`, `*.bundle.js`) are lowered one severity level and tagged `context: test`, `docs` or `generated`. Real provider keys are not lowered, because they leak from tests too.
- **Rule confidence.** Rules that flag a risky API without evidence of untrusted input (for example `knex.raw()`, `[AllowAnonymous]`, `unsafe {}`) are `confidence: low`. They are still reported, but do not trigger `--fail-on` unless you pass `--fail-on-low-confidence` or set `fail_on_low_confidence: true` in `.argus.yml`.

Malware rules are exempt from all three: code under review must not be able to hide itself with a comment or by sitting in a `tests/` folder.

### Baseline diff (PR-only new findings)

```bash
# Save baseline from main
argus scan all . --format json -o baseline.json

# On PR — compare against baseline
argus scan all . --baseline baseline.json --format json -o current.json
argus compare baseline.json current.json --fail-on-new

# Or set in .argus.yml:
# baseline: .argus/baseline.json
# fail_on_new_only: true
```

### Secret remediation guidance

Secret findings include step-by-step rotate/revoke guidance (AWS, GitHub tokens, private keys, Stripe, etc.):

```bash
argus scan secrets . --format json   # fix_guidance on each finding
# MCP apply_fix for secrets returns remediation steps (no auto-fix)
```

### Database security rules

Built-in static rules for SQL injection, connection strings, migration GRANTs, ORM raw queries:

- **JavaScript / TypeScript ORMs** (both packages): values interpolated into TypeORM `.where()` / `.andWhere()` / `.having()`, Knex `whereRaw` / `orderByRaw` / `knex.raw`, Prisma `$queryRawUnsafe` / `$executeRawUnsafe` / `Prisma.raw`, and `sequelize.literal()`. Named parameters, bindings and tagged templates are not flagged, nor are `${UPPER_CASE}` constants. An `ORDER BY` column taken from the request is reported as low confidence: check it is limited to an allow-list.

```bash
argus scan code .    # includes database.yaml rules via argus-languages
```

Full docs: [docs/features-roadmap.md](docs/features-roadmap.md) · [API reference](docs/api-reference.md)

---

## Cloud dashboard upload (optional)

Send scan results to the Argus cloud dashboard when `ARGUS_API_KEY` is set. Local scans still work without any key.

```bash
export ARGUS_API_URL=http://localhost:4000/v1   # default
export ARGUS_API_KEY=arg_live_PASTE_YOUR_KEY

argus scan all /path/to/project                 # uploads automatically
argus scan sast . --upload --fail-on high       # force upload
argus scan secrets . --no-upload                # skip upload
```

**MCP** — add env to your IDE's MCP config (e.g. Cursor `~/.cursor/mcp.json`, VS Code MCP settings, Claude Desktop config):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"],
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Print the same template: `argus mcp --config`

After each MCP scan or CLI scan, results upload to `{ARGUS_API_URL}/scans` with repo/branch/commit from git. Full setup: [docs/AGENT-UPLOAD.md](docs/AGENT-UPLOAD.md)

---

## Versions

Each package has its own version number. These are the versions released together:

<!-- versions:start -->
| Package | Version | Install |
|---|---|---|
| `argus-scan` (CLI + MCP) | 0.10.1 | `pip install argus-scan==0.10.1` (needs `argus-languages>=0.8.1`) |
| `argus-languages` (built-in rules) | 0.8.1 | `pip install argus-languages==0.8.1` |
| `argus-codescan` (npm) | 0.12.1 | `npx argus-codescan@0.12.1` |
| VS Code extension | 0.1.0 | Marketplace: `arestechub.argus-scan` |
<!-- versions:end -->

`argus-scan` always requires the `argus-languages` version it was tested with. Maintainers: `python scripts/versions.py bump --scan X --languages Y --npm Z` updates every file and this table, and `python scripts/versions.py check` (run in CI) fails when anything is out of sync.

## Install

Pick the package that matches your project:

| Your project | Install | Scan command |
|--------------|---------|--------------|
| **React / Next.js / Node** | `npm install -D argus-codescan` | `npx argus-codescan scan all .` |
| **Java, PHP, Flutter, Terraform, Ansible** | `pip install argus-languages` | `argus-languages scan /path/to/project` |
| **Full suite (MCP, DAST, IaC tools)** | `pip install argus-scan` | `argus scan all /path/to/project` |

### React / Node (npm) — no Python required

```bash
npm install -D argus-codescan

npx argus-codescan scan sca .       # dependencies (npm audit)
npx argus-codescan scan sast .      # source code (JS/TS)
npx argus-codescan scan secrets .   # API keys, tokens
npx argus-codescan scan all .       # everything

# CSV report written automatically (or set path with --output)
npx argus-codescan scan all . --output ./reports/security.csv
```

Add to `package.json`:

```json
{
  "scripts": {
    "security:scan": "argus-codescan scan sca . --output ./reports/deps.csv",
    "security:code": "argus-codescan scan sast . --output ./reports/code.csv",
    "security:secrets": "argus-codescan scan secrets . --output ./reports/secrets.csv",
    "security:all": "argus-codescan scan all . --output ./reports/full.csv"
  }
}
```

### Java, PHP, Flutter, IaC (pip — lightweight)

```bash
pip install argus-languages

# Any supported language / IaC in one command
argus-languages scan /path/to/project

# Examples
argus-languages scan ./my-java-app
argus-languages scan ./terraform
argus-languages scan ./flutter-app
```

### Full Argus CLI + MCP (pip)

```bash
pip install argus-scan
# With all Python-native scanners:
pip install "argus-scan[all-tools]"

argus scan code /path/to/project    # built-in multi-language (uses argus-languages)
argus scan sast /path/to/project    # + Semgrep, Bandit, ESLint if installed
argus scan terraform /path/to/infra
argus scan ansible /path/to/playbooks
argus scan all /path/to/project --fail-on high
argus scan all /path/to/project --upload          # cloud dashboard (needs ARGUS_API_KEY)
argus scan all . --format sarif -o argus.sarif    # GitHub Code Scanning export
argus compare baseline.json current.json          # diff two scan JSON files
argus tools                         # show installed scanners
argus mcp                           # start MCP server for any MCP-compatible IDE
argus mcp --config                  # print MCP config with cloud env vars
```

### Zero-install

```bash
uvx argus-scan       # full Python CLI via uv
npx argus-codescan   # Node/React via npm
```

### Go (single binary)

```bash
go install github.com/argus-code-scanning/argus-codescan-mcp/packages/go/cmd/argus@latest
```

### Shell script

```bash
curl -sSfL https://raw.githubusercontent.com/argus-code-scanning/argus-codescan-mcp/main/packages/shell/install.sh | sh
```

### Docker (all scanners bundled)

```bash
docker pull ghcr.io/okirigabriel/argus-codescan-mcp:latest

# MCP server (add to ~/.cursor/mcp.json — see packages/docker/README.md)
docker run --rm -i -v "$(pwd):/workspace" ghcr.io/okirigabriel/argus-codescan-mcp

# One-shot CLI scan
docker run --rm -v "$(pwd):/workspace" ghcr.io/okirigabriel/argus-codescan-mcp \
  scan all /workspace
```

Full Docker guide: [packages/docker/README.md](packages/docker/README.md)

### VS Code Extension

Install **Argus Security Scanner** from the VS Code Marketplace.

---

## Quick Start

### React / Next.js

```bash
npm install -D argus-codescan
npm run security:all   # after adding scripts — see Install section above
```

### Flutter / Java / PHP / Terraform

```bash
pip install argus-languages
argus-languages scan /path/to/project
```

### Full CLI (all scan types)

```bash
pip install "argus-scan[all-tools]"
argus tools
argus scan code /path/to/project
argus scan terraform /path/to/infra
argus scan all /path/to/project --format table
argus scan all /path/to/project --fail-on high
```

### MCP (any MCP-compatible IDE)

Add to your MCP client config (e.g. Cursor `~/.cursor/mcp.json`, VS Code MCP settings, Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"],
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Omit the `env` block if you only want local scans (no cloud upload). Or zero-install with `uvx`:

```json
{
  "mcpServers": {
    "argus": { "command": "uvx", "args": ["argus-scan", "mcp"] }
  }
}
```

Then ask your AI:
```
Scan /path/to/myproject for security vulnerabilities
Are there any hardcoded secrets in this repo?
Fix the high-severity finding in src/api.js line 42
Run a full security audit and give me a prioritised fix list
```

---

## Install Scanners

Run `argus tools` to see what's installed. Quick install for common tools:

```bash
# macOS
brew install semgrep trivy gitleaks trufflehog tfsec tflint kics
pip install bandit safety pip-audit detect-secrets checkov ansible-lint
docker pull ghcr.io/zaproxy/zaproxy:stable   # OWASP ZAP

# Linux
pip install "argus-scan[all-tools]"
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

Full guide: [docs/tool-setup.md](docs/tool-setup.md)

---

## Do I Need a Token or Subscription?

**No Argus subscription** for local scanning. Every scanner runs on your machine:

| Layer | Cost | Requires |
|-------|------|---------|
| Argus CLI & MCP | Free | Python 3.10+ |
| Semgrep, Trivy, Bandit, tfsec… | Free | Local install |
| Cloud dashboard upload | Optional | `ARGUS_API_KEY` from your dashboard |
| AI client (Cursor, Claude) | Subscription | Only for chat-driven scans and fixes |

The AI subscription is for the **AI client**, not for Argus. Cloud upload uses your **Argus API key** (`arg_live_…`), not your Cursor/Claude token.

---

## Repository Structure

```
argus-codescan-mcp/
├── packages/
│   ├── python/          pip install argus-scan
│   │   └── src/argus/
│   │       ├── cli.py             Standalone CLI
│   │       ├── server.py          MCP server
│   │       ├── cloud_upload.py    Optional dashboard upload
│   │       └── tools/             SAST, DAST, SCA, secrets, IaC, …
│   ├── languages/       pip install argus-languages  ← Java, PHP, Terraform, Ansible, all code
│   │   └── src/argus_languages/
│   │       └── bundled_rules/     YAML rules shared across Python (and future Go client)
│   ├── npm/             npx argus-codescan  (Node.js / JS-TS only)
│   ├── go/              go install .../argus@latest
│   ├── shell/           curl | sh installer
│   └── docker/          ghcr.io/okiriGabriel/argus-codescan-mcp
├── extensions/
│   └── vscode/          Argus Security Scanner VS Code extension
├── docs/
│   ├── getting-started.md
│   ├── architecture.md
│   ├── api-reference.md
│   ├── AGENT-UPLOAD.md
│   └── tool-setup.md
└── .github/
    ├── workflows/        CI for Python, npm, Go, VS Code, Docker
    └── ISSUE_TEMPLATE/
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Getting Started](docs/getting-started.md) | Install, configure, first scan |
| [Architecture](docs/architecture.md) | How Argus works under the hood |
| [API Reference](docs/api-reference.md) | All MCP tools, parameters, schemas |
| [Agent Upload](docs/AGENT-UPLOAD.md) | Cloud dashboard upload & API keys |
| [Privacy & data](docs/privacy-and-data.md) | What stays local vs cloud/CI egress |
| [Tool Setup](docs/tool-setup.md) | Install every scanner on every platform |
| [Contributing](CONTRIBUTING.md) | Add scanners, clients, and fixes |
| [Add a YAML rule](docs/contributing-rules.md) | 5-minute guide to extend malware/ML/DB rules |
| [MCP Prompt Cookbook](docs/mcp-prompt-cookbook.md) | 8 example prompts for Argus MCP scans |
| [Security Policy](SECURITY.md) | Report vulnerabilities |

---

## Contributing

**Everyone is welcome to contribute**, whether it's your first open-source PR or your hundredth. Start with the pinned **[👋 Contributors welcome](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/103)** issue.

| | |
|---|---|
| 🟢 [Good first issues](https://github.com/argus-code-scanning/argus-codescan-mcp/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22+no%3Aassignee) | Small, self-contained tasks: docs, YAML rules, CI workflows |
| 🙋 [Help wanted](https://github.com/argus-code-scanning/argus-codescan-mcp/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22+no%3Aassignee) | Bigger features: scanners, privacy controls, integrations |
| ⚡ [Add a YAML rule](docs/contributing-rules.md) | Fastest first PR: one detection rule plus a test |

To claim an issue, comment "I'd like to work on this" with a short plan and a maintainer will assign it. Setup, code style and PR checklist: [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

Created and maintained by **Okiri Gabriel** ([@OkiriGabriel](https://github.com/OkiriGabriel)) · Website: https://code-scan.arestechub.com/

Argus is free and open source under the MIT license, built in the open with its contributors. Anyone can use, modify and redistribute it, and contributions are welcome (see [Contributing](#contributing)).

### Credit

If you use, fork or build on Argus, please credit it: keep the copyright notice and [LICENSE](LICENSE) (the MIT license requires this), and mention **Argus by Okiri Gabriel** with a link to this repository in your README, docs or about page. Third-party scanners and data Argus works with are listed in [NOTICE](NOTICE).

## License

MIT - see [LICENSE](LICENSE)
