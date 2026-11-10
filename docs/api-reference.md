# MCP API Reference

All tools communicate via the [Model Context Protocol](https://modelcontextprotocol.io/) JSON-RPC 2.0 over stdio.

---

## Documentation resources

MCP clients can discover these read-only resources with `resources/list` and
retrieve their contents with `resources/read`. Each resource returns JSON with
an `application/json` MIME type.

| URI | Contents |
|-----|----------|
| `argus://schema/finding` | JSON Schema derived from the public Finding model, excluding the internal raw scanner payload. |
| `argus://scan-types` | Scan category identifiers and the registered MCP tools for those categories. |
| `argus://workflows` | Example requests for staged review and source/dependency scanning, with interpretation guidance. |

Reading resources does not scan a project, read source files or contact external
services. Example paths are placeholders to replace before invoking scan tools.
Invoking those tools can run external scanners with their normal network access.
Unknown resource URIs return a protocol error rather than reading arbitrary paths.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/read",
  "params": {"uri": "argus://schema/finding"}
}
```

---

## `scan_sast`

Run Static Application Security Testing on source code.

**Supported languages:** Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C/C++, C#, Kotlin, Rust, and more (via Semgrep).

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Absolute path to file or directory |
| `tools` | `string[]` | ❌ | all | Subset: `["semgrep", "bandit", "eslint"]` |
| `semgrep_config` | `string` | ❌ | `"auto"` | Semgrep ruleset. Examples: `"auto"`, `"p/owasp-top-ten"`, `"p/python"`, `"p/javascript"`, `"p/ci"` |
| `timeout` | `integer` | ❌ | `300` | Per-tool timeout in seconds |

### Example

```json
{
  "name": "scan_sast",
  "arguments": {
    "target": "/home/user/myapp",
    "semgrep_config": "p/owasp-top-ten",
    "timeout": 120
  }
}
```

### Response

Markdown report + collapsible raw JSON. Findings include: severity, file, line, description, CWE, fix guidance.

---

## `scan_dast`

Dynamic scan of a **live, running** web application.

> ⚠️ The target URL must be an accessible running service. Do not scan production systems without authorisation.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target_url` | `string` | ✅ | — | URL of running app (`http://localhost:3000`) |
| `tools` | `string[]` | ❌ | all | Subset: `["zap", "nikto"]` |
| `timeout` | `integer` | ❌ | `600` | Timeout in seconds (DAST scans are slow) |

### ZAP Resolution Order

1. `docker run ghcr.io/zaproxy/zaproxy:stable zap-baseline.py` (recommended)
2. Local `zap-baseline.py` on PATH
3. Error with install instructions

---

## `scan_sca`

Software Composition Analysis — scan third-party dependencies for known CVEs.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Project directory or dependency file |
| `tools` | `string[]` | ❌ | all | Subset: `["trivy", "safety", "pip-audit", "npm-audit", "govulncheck", "composer-audit"]` |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

### Supported Manifests

`requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `pom.xml`, `build.gradle` (via Trivy).

Ecosystem tools scan **every** matching project under `target` (skipping `node_modules`, `vendor`, virtualenvs):

| Tool | Manifests | Notes |
|------|-----------|-------|
| `pip-audit` | every `requirements*.txt` and `pyproject.toml` | Audits the project's declared dependencies, never the environment Argus runs in. Severity comes from OSV (GHSA); falls back to `high` offline. |
| `npm-audit` | every `package.json` with a `package-lock.json` / `npm-shrinkwrap.json` | One finding per advisory (GHSA id in `cve`). Descriptions start with `[runtime dependency]` or `[dev dependency]`. Packages without a lockfile are listed in `errors`. |
| `govulncheck` | every `go.mod` | Runs only when a `go.mod` exists. `[called]` findings (your code reaches the vulnerable function) keep their advisory severity and point at the call site; `[not called]` ones are `low`. |
| `composer-audit` | every `composer.lock` | Runs only when a `composer.lock` exists. Marks `[runtime dependency]` / `[dev dependency]`. |

---

## `scan_secrets`

Detect leaked credentials, API keys, tokens, and private keys in source code.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Directory or git repository path |
| `tools` | `string[]` | ❌ | all | Subset: `["gitleaks", "detect-secrets", "trufflehog"]` |
| `timeout` | `integer` | ❌ | `180` | Timeout in seconds |

### What Gets Detected

AWS keys, Azure storage keys, GitHub tokens, Stripe/Twilio/SendGrid API keys, JWT tokens, private RSA/EC keys, basic auth credentials, high-entropy strings, and more.

---

## `scan_iac`

Scan Infrastructure-as-Code files for security misconfigurations.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | IaC file or directory |
| `framework` | `string` | ❌ | auto | `terraform`, `cloudformation`, `kubernetes`, `dockerfile`, `helm`, `ansible`, `arm` |
| `tools` | `string[]` | ❌ | all | Subset: `["checkov", "trivy-config", "terrascan"]` |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

### Supported Frameworks

| Framework | Checkov | Trivy | Terrascan |
|-----------|---------|-------|-----------|
| Terraform | ✅ | ✅ | ✅ |
| Kubernetes | ✅ | ✅ | ✅ |
| Dockerfile | ✅ | ✅ | ❌ |
| CloudFormation | ✅ | ❌ | ✅ |
| Helm | ✅ | ✅ | ❌ |
| Ansible | ✅ | ❌ | ❌ |
| ARM Templates | ✅ | ❌ | ❌ |

---

## `scan_terraform`

Dedicated scan for Terraform infrastructure code (`.tf` files).

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Path to Terraform directory or `.tf` file |
| `tools` | `string[]` | ❌ | all | Subset: `["tfsec", "tflint", "terraform-validate", "kics", "checkov"]` |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

### What Gets Detected

| Tool | Detects |
|------|---------|
| **tfsec** | Unencrypted S3/EBS/RDS, public exposure, open security groups, missing logging, hardcoded secrets |
| **tflint** | Invalid resource arguments, deprecated resources, naming violations, provider-specific issues |
| **terraform validate** | Syntax errors, missing required arguments, invalid references |
| **KICS** | 2000+ Terraform queries — IAM policy issues, network exposure, encryption, monitoring gaps |
| **Checkov** | CIS benchmark violations, NIST controls, PCI-DSS/HIPAA policies |

---

## `scan_ansible`

Dedicated scan for Ansible playbooks, roles, and collections.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Path to playbook, role directory, or project root |
| `tools` | `string[]` | ❌ | all | Subset: `["ansible-lint", "kics", "checkov"]` |
| `ansible_lint_profile` | `string` | ❌ | `"safety"` | Strictness: `min`, `basic`, `moderate`, `safety`, `shared`, `production` |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

### ansible-lint Profiles

| Profile | Use Case |
|---------|---------|
| `min` | Only failures that break playbook execution |
| `basic` | Essential best practices |
| `moderate` | Reasonable recommendations |
| `safety` | Security-focused rules (default) |
| `shared` | For public/shared roles |
| `production` | All rules — strictest |

### What Gets Detected

| Tool | Detects |
|------|---------|
| **ansible-lint** | Hardcoded passwords, missing `no_log`, risky shell pipes, unsafe file permissions, partial become, deprecated modules |
| **KICS** | Hardcoded secrets in vars, insecure SSH config, root execution, exposed secrets in templates |
| **Checkov** | CKV2_ANSIBLE rules — unencrypted secrets, missing vault, insecure shell usage |

---

## `scan_container`

Scan a container image for OS package vulnerabilities.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `image` | `string` | ✅ | — | Image name (`nginx:latest`, `ghcr.io/org/app:1.0`) |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

---

## `scan_all`

Run a full security audit. Parallelises SAST + SCA + Secrets + IaC, then optionally DAST and container scans.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Project directory |
| `target_url` | `string` | ❌ | — | URL for DAST scan |
| `container_image` | `string` | ❌ | — | Image for container scan |
| `timeout` | `integer` | ❌ | `300` | Per-tool timeout |
| `format` | `string` | ❌ | `"markdown"` | `"markdown"` or `"json"` |

---

## `check_tools`

List which scanners are installed and provide installation commands for missing ones.

### Parameters

None.

### Response

Markdown table showing tool name, category, install status, and install command.

---

## `get_fix_plan`

Build a structured remediation plan from a previous aggregated scan report.
This tool processes the supplied JSON in memory without running scanners,
modifying files or calling external services.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_result_json` | `string` | Yes | JSON string containing an AggregatedReport with a `results` array and a `findings` array in each result. |

### Example

```json
{
  "name": "get_fix_plan",
  "arguments": {
    "scan_result_json": "{\"target\":\"/project\",\"results\":[{\"tool\":\"semgrep\",\"scan_type\":\"sast\",\"findings\":[{\"title\":\"SQL injection\",\"rule_id\":\"sql-injection\",\"severity\":\"high\",\"file\":\"app.py\",\"line\":12,\"fix_guidance\":\"Use parameterised queries.\"}]}]}"
  }
}
```

### Response

The response text contains a JSON object with `target`, `summary`, `groups` and
`warnings`. The summary counts `total_findings` and `fix_groups`.

Each group contains a one-based `priority`, `severity`, `scan_type`, `tool`,
`rule_id`, `title`, `finding_count`, `locations`, `fix_guidance` and `references`.
Findings are grouped by scan type, scanner and rule identifier, with the title
used when no rule identifier is present. The group takes its highest finding
severity. Groups are ordered critical, high, medium, low, info and unknown, with
scan type, scanner, rule and title breaking ties. Unrecognised severity strings
are treated as unknown.

Locations retain file, line and column values for every occurrence. Existing
guidance and references are collected without duplicates; secret findings without
guidance use the existing rotation checklist. No general fix text is invented
when a scanner provides none. Warnings preserve scan errors and unavailable-tool
notices so an empty plan does not hide incomplete scan coverage.

Malformed reports return an explanatory validation message. The report must be
an aggregated report rather than a single finding or scanner result.

---

## `get_scan_report`

Reformat a raw JSON scan result as Markdown.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_result_json` | `string` | ✅ | JSON from a previous scan |
| `format` | `string` | ❌ | `"markdown"` or `"json"` |

---

## `explain_finding`

Explain a supplied finding using its scanner context, remediation guidance and
CWE identifiers. The tool supports every scan category in the public model,
including secrets, SCA, IaC, DAST and SAST.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `finding` | `object` | Yes | Finding from a scan report, including non-empty `title`, `severity`, `scan_type` and `tool` fields. |
| `code_snippet` | `string` | No | Optional caller-supplied snippet text to include in the explanation and review prompt. |

The finding can also include `file`, `line`, `column`, `description`, `rule_id`,
`fix_guidance`, `references`, `cwe` and `cve`. Severity and scan category values
follow the public model enums. CWE values accept numeric identifiers or strings
such as `CWE-79`, including the stringified lists produced by some scanners.

### Example

```json
{
  "name": "explain_finding",
  "arguments": {
    "finding": {
      "title": "Potential SQL injection",
      "severity": "high",
      "scan_type": "sast",
      "tool": "semgrep",
      "file": "app.py",
      "line": 12,
      "cwe": "CWE-89",
      "fix_guidance": "Use parameterised queries."
    },
    "code_snippet": "cursor.execute(query)"
  }
}
```

### Response

The response text contains JSON with `finding`, `explanation`, `cwe_ids`,
`fix_guidance`, `rotation_checklist`, `references` and `review_prompt`. It includes
`code_snippet` only when the caller supplies one. The review prompt combines
verification instructions with the structured finding context.

Existing scanner guidance is retained. Secret findings always include the
existing provider-specific or generic rotation checklist. Other findings without
scanner guidance receive category-specific review steps rather than an invented
fix. CWE links are built only from supplied identifiers and are not fetched.

The tool makes no external service calls, runs no scanners and applies no fixes.
File paths are descriptive metadata and are never opened. Supplied description
and snippet text are preserved; this endpoint does not implement report redaction.
Internal raw scanner payloads are excluded from the explanation and prompt.
Malformed finding fields return an explanatory validation message.

---

## `apply_fix`

Preview or apply a fix for a **specific finding**. Only call when the user explicitly asks — scans never modify files.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | `string` | ✅ | — | Project root or scan target |
| `file` | `string` | ✅ | — | File path from the finding |
| `tool` | `string` | ✅ | — | Scanner tool (e.g. `semgrep`, `eslint-security`) |
| `scan_type` | `string` | ❌ | `"sast"` | Scan type from the finding |
| `rule_id` | `string` | ❌ | `""` | Rule ID |
| `line` | `integer` | ❌ | `0` | Line number |
| `fix_guidance` | `string` | ❌ | `""` | Guidance text from the finding |
| `apply` | `boolean` | ❌ | `false` | Run automated fix (only after user confirms) |
| `semgrep_config` | `string` | ❌ | `"auto"` | Semgrep config for semgrep fixes |
| `timeout` | `integer` | ❌ | `120` | Fix command timeout |

### Behavior

| `apply` | Result |
|---------|--------|
| `false` | Returns fix guidance and whether autofix is available |
| `true` | Runs ESLint `--fix` or Semgrep `--autofix` on the file |

**Never auto-fix:** secrets, SCA, DAST, and container findings — guidance only.

### Example (guidance only)

```json
{
  "name": "apply_fix",
  "arguments": {
    "target": "/home/user/myapp",
    "file": "src/api.js",
    "tool": "eslint-security",
    "rule_id": "security/detect-eval-with-expression",
    "line": 42,
    "fix_guidance": "Avoid eval() with dynamic expressions",
    "apply": false
  }
}
```

---

## Finding Schema

Every finding returned by any tool is normalised to this shape:

```json
{
  "title": "SQL Injection via string concatenation",
  "severity": "high",
  "scan_type": "sast",
  "tool": "semgrep",
  "file": "app/routes.py",
  "line": 42,
  "column": 8,
  "description": "User-controlled input used in raw SQL query",
  "cwe": "CWE-89",
  "cve": "",
  "fix_guidance": "Use parameterised queries or an ORM",
  "rule_id": "python.sqlalchemy.security.audit.avoid-sqlalchemy-text",
  "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
}
```

### Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Immediate exploitation risk (e.g. RCE, hardcoded credentials) |
| `high` | Significant security risk, should fix before deployment |
| `medium` | Moderate risk, fix in next sprint |
| `low` | Best-practice deviation, low exploitability |
| `info` | Informational, no direct security impact |
| `unknown` | Severity not reported by the tool |

---

## `compare_scans`

Diff two scan JSON reports (baseline vs current). Returns new, fixed, and unchanged findings.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `baseline_json` | `string` | ✅ | — | JSON string of baseline `AggregatedReport` |
| `current_json` | `string` | ✅ | — | JSON string of current `AggregatedReport` |
| `format` | `string` | ❌ | `"json"` | `"json"` or `"markdown"` |

### CLI equivalent

```bash
argus compare baseline.json current.json --fail-on-new
```

---

## Output formats

| Format | CLI | MCP | Use case |
|--------|-----|-----|----------|
| `markdown` | ✅ | ✅ | Human-readable reports |
| `json` | ✅ | ✅ | CI artifacts, baseline storage |
| `sarif` | ✅ | ✅ | GitHub Code Scanning upload |
| `table` | ✅ | ❌ | Terminal summary |

SARIF export: `argus scan code . --format sarif -o argus.sarif`

### Changed-file scans (pull requests)

`argus scan sast`, `argus scan secrets`, and the other file-based scan commands accept `--paths-file`. Each line is scanned on its own and the findings are merged into one report. `argus ci pr-paths` builds that list from `git diff` and falls back to a full scan when the diff is larger than `--limit` (default 50).

Findings include `data_classification` (`pii`, `phi`, `pci`, `confidential`, `public`, or `unset`). Existing scanner integrations default to `unset`. Built-in YAML rules can declare a `classification` value, which is included in JSON and SARIF rule tags. Filter displayed findings with a comma-separated classification list, for example `argus scan all . --classification pii,phi`; this filter does not change the CI exit decision from `--fail-on`.

```bash
argus ci pr-paths --base "$BASE_SHA" --limit 50 -o scan-paths.txt
argus scan sast . --paths-file scan-paths.txt --format sarif -o sast.sarif
argus scan secrets . --paths-file scan-paths.txt --format sarif -o secrets.sarif
```

### Temp files and `--no-persist`

`argus scan …` and `argus review` accept `--no-persist` (report to stdout only; `--output` is rejected) and `--artifacts-dir DIR`. Either one keeps the temp files of Argus and of every scanner it launches in a private `0700` directory, which is deleted after the run. See [privacy-and-data.md](privacy-and-data.md#scan-artifacts-on-disk).

```bash
argus scan secrets . --no-persist --format json | jq '.summary'
argus scan sast . --artifacts-dir "$RUNNER_TEMP" --format sarif -o sast.sarif
```

### Pull request comment

`argus ci pr-comment` turns those SARIF files into a Markdown comment: a severity table per tool, links to the CI run and cloud dashboard, the top fix suggestions (same order as `fix_plan`), and a collapsible prompt for an AI assistant. Missing SARIF files are skipped and called out in the comment.

```bash
argus ci pr-comment \
  --sarif sast.sarif secrets.sarif \
  --scope-mode changed --changed-count 4 \
  --run-url "$RUN_URL" \
  --dashboard-url "$ARGUS_DASHBOARD_URL" \
  --max-suggestions 5 \
  -o argus-pr-comment.md
```

`.github/workflows/argus-sarif.yml` posts it as the `github-actions` bot and edits the same comment on each push (it finds the `<!-- argus-pr-comment -->` marker). The job needs `pull-requests: write`. Set the repository variable `ARGUS_DASHBOARD_URL` to add the dashboard link. Pull requests from forks get a read-only token, so for them the comment appears only in the job summary.

See [features roadmap](features-roadmap.md) for `.argus.yml` policy and baseline diff workflows.
