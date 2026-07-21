# MCP API Reference

All tools communicate via the [Model Context Protocol](https://modelcontextprotocol.io/) JSON-RPC 2.0 over stdio.

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
| `tools` | `string[]` | ❌ | all | Subset: `["trivy", "safety", "pip-audit", "npm-audit"]` |
| `timeout` | `integer` | ❌ | `300` | Timeout in seconds |

### Supported Manifests

`requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `pom.xml`, `build.gradle` (via Trivy).

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

## `get_scan_report`

Reformat a raw JSON scan result as Markdown.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_result_json` | `string` | ✅ | JSON from a previous scan |
| `format` | `string` | ❌ | `"markdown"` or `"json"` |

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
