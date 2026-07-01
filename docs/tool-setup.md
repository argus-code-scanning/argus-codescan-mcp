# Tool Setup Guide

This guide covers installing every scanner that `argus-scan` integrates. All tools are optional — the server reports which are unavailable and how to install them.

---

## Install Everything at Once

### macOS
```bash
# Homebrew bundle
brew install semgrep trivy gitleaks trufflehog nikto terrascan

# Python tools
pip install "argus-scan[all-tools]"
# Installs: semgrep bandit flake8 flake8-bandit safety pip-audit detect-secrets checkov

# Node.js tools
npm install -g eslint eslint-plugin-security

# OWASP ZAP via Docker (recommended)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### Ubuntu / Debian
```bash
# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4)
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_linux_x64.tar.gz" | tar -xz -C /usr/local/bin

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Terrascan
curl -L https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz | tar -xz terrascan && mv terrascan /usr/local/bin

# Nikto (Debian/Ubuntu)
sudo apt install -y nikto

# Python tools
pip install "argus-scan[all-tools]"

# Node.js tools
npm install -g eslint eslint-plugin-security

# OWASP ZAP via Docker
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### Windows (PowerShell)
```powershell
# Scoop
scoop install trivy gitleaks

# Python tools
pip install "argus-scan[all-tools]"

# Node.js tools
npm install -g eslint eslint-plugin-security

# OWASP ZAP via Docker Desktop
docker pull ghcr.io/zaproxy/zaproxy:stable
```

---

## Tool Details

### Semgrep — SAST (all languages)

- **Website:** https://semgrep.dev
- **Languages:** Python, JS/TS, Go, Java, Ruby, PHP, C/C++, C#, Kotlin, Rust, and more
- **Install:** `pip install semgrep` or `brew install semgrep`
- **Free tier:** Yes, with `--config auto`
- **Popular configs:**
  ```bash
  semgrep --config auto              # Auto-detect best rules
  semgrep --config p/owasp-top-ten   # OWASP Top 10
  semgrep --config p/python          # Python-specific
  semgrep --config p/javascript      # JS/TS-specific
  semgrep --config p/golang          # Go-specific
  semgrep --config p/java            # Java-specific
  semgrep --config p/ci              # CI-friendly rules
  ```

### Bandit — SAST (Python)

- **Website:** https://bandit.readthedocs.io
- **Languages:** Python only
- **Install:** `pip install bandit`
- **Checks:** Hardcoded passwords, SQL injection, shell injection, insecure deserialization, weak crypto, and more

### ESLint Security — SAST (JavaScript/TypeScript)

- **Website:** https://github.com/eslint-community/eslint-plugin-security
- **Languages:** JavaScript, TypeScript, JSX, TSX
- **Install:** `npm install -g eslint eslint-plugin-security`
- **Checks:** Object injection, unsafe regexes, non-literal require, eval, buffer issues, timing attacks

### OWASP ZAP — DAST

- **Website:** https://www.zaproxy.org
- **Type:** Active + passive web scanner
- **Best install (Docker):**
  ```bash
  docker pull ghcr.io/zaproxy/zaproxy:stable
  ```
- **Local install (macOS):**
  ```bash
  brew install owasp-zap
  ```
- **Usage:** The MCP server uses the `zap-baseline.py` script which runs a passive scan suitable for CI/CD without needing authentication.

### Nikto — DAST

- **Website:** https://cirt.net/Nikto2
- **Type:** Web server scanner (checks for outdated software, dangerous files, misconfigs)
- **Install:**
  ```bash
  brew install nikto          # macOS
  apt install nikto           # Debian/Ubuntu
  ```

### Trivy — SCA + IaC + Container

- **Website:** https://aquasecurity.github.io/trivy
- **Modes used:**
  - `trivy fs` — filesystem/dependency scan
  - `trivy config` — IaC misconfiguration scan
  - `trivy image` — container image scan
- **Install:**
  ```bash
  brew install trivy                  # macOS
  # Linux:
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  ```
- **Coverage:** 150+ programming languages, all major OS package managers, Dockerfile, Terraform, Kubernetes, Helm, CloudFormation

### Safety — SCA (Python)

- **Website:** https://pyup.io/safety
- **Languages:** Python (requirements.txt, Pipfile.lock, poetry.lock)
- **Install:** `pip install safety`
- **Database:** PyUp.io vulnerability database (requires free API key for latest data)

### pip-audit — SCA (Python)

- **Website:** https://pypi.org/project/pip-audit
- **Languages:** Python
- **Install:** `pip install pip-audit`
- **Database:** PyPI Advisory Database + OSV

### npm audit — SCA (Node.js)

- **Built into npm** — no additional install needed
- **Languages:** JavaScript, TypeScript (Node.js)
- **Database:** GitHub Advisory Database

### Gitleaks — Secret Scanning

- **Website:** https://github.com/gitleaks/gitleaks
- **Install:**
  ```bash
  brew install gitleaks       # macOS
  go install github.com/gitleaks/gitleaks/v8@latest  # Go
  ```
- **Coverage:** 150+ secret patterns (AWS, GCP, Azure, GitHub, Stripe, Twilio, etc.)
- **Git-aware:** Scans all commits in history, not just current files

### detect-secrets — Secret Scanning

- **Website:** https://github.com/Yelp/detect-secrets
- **Install:** `pip install detect-secrets`
- **Approach:** Uses entropy analysis + keyword detection. Produces a baseline file to track known false positives.

### TruffleHog — Secret Scanning

- **Website:** https://github.com/trufflesecurity/trufflehog
- **Install:**
  ```bash
  brew install trufflehog     # macOS
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
  ```
- **Unique feature:** Verifies secrets are still active (not just patterns), reducing false positives

### tfsec — Terraform SAST

- **Website:** https://aquasecurity.github.io/tfsec
- **Install:**
  ```bash
  brew install tfsec              # macOS
  go install github.com/aquasecurity/tfsec/cmd/tfsec@latest  # Go
  # Note: tfsec functionality is also embedded in Trivy:
  trivy config --scanners misconfig /path/to/tf
  ```
- **Checks:** Unencrypted storage, publicly exposed resources, open security group rules (0.0.0.0/0), missing logging/audit trails, hardcoded sensitive values

### tflint — Terraform Linter

- **Website:** https://github.com/terraform-linters/tflint
- **Install:**
  ```bash
  brew install tflint             # macOS
  curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash  # Linux
  ```
- **Checks:** Invalid provider-specific resource attributes, deprecated resources, variable naming, unused declarations
- **Plugins:** Install AWS/GCP/Azure plugins for provider-specific rules:
  ```bash
  tflint --init   # after placing .tflint.hcl with plugin config
  ```

### KICS — Multi-framework IaC Scanner

- **Website:** https://kics.io
- **Install:**
  ```bash
  brew install kics               # macOS
  go install github.com/Checkmarx/kics/v2@latest  # Go
  # Docker:
  docker run --rm -v $(pwd):/path checkmarx/kics scan -p /path
  ```
- **Coverage:** Terraform, Ansible, Kubernetes, Dockerfile, CloudFormation, Helm, ARM, Pulumi — 2000+ queries
- **Categories:** Encryption, network exposure, IAM permissions, logging, access control

### ansible-lint — Ansible Security Linter

- **Website:** https://ansible.readthedocs.io/projects/lint
- **Install:**
  ```bash
  pip install ansible-lint        # pip
  pipx install ansible-lint       # pipx (isolated)
  brew install ansible-lint       # macOS Homebrew
  ```
- **Key security rules:**
  | Rule | Description |
  |------|-------------|
  | `no-log-password` | Passwords must have `no_log: true` |
  | `risky-shell-pipe` | Dangerous pipe usage in shell tasks |
  | `risky-file-permissions` | World-writable file modes |
  | `command-instead-of-shell` | Prefer `command` over `shell` module |
  | `partial-become` | Incomplete privilege escalation setup |
  | `yaml[truthy]` | Unquoted `yes`/`no` in YAML |

### Checkov — IaC

- **Website:** https://www.checkov.io
- **Install:** `pip install checkov`
- **Coverage:** Terraform, CloudFormation, Kubernetes, Dockerfile, Helm, ARM, Ansible, Serverless Framework
- **Rule count:** 1000+ built-in policies (CIS benchmarks, NIST, PCI-DSS, HIPAA)

### Terrascan — IaC

- **Website:** https://runterrascan.io
- **Install:**
  ```bash
  brew install terrascan      # macOS
  curl -L https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz | tar -xz && mv terrascan /usr/local/bin
  ```
- **Coverage:** Terraform, Kubernetes, Helm, Kustomize, Dockerfile, CloudFormation

---

## Verifying Your Setup

Run the `check_tools` MCP tool or:

```bash
# From the CLI
argus-scan --check   # (shell wrapper)

# Or ask the AI
# "Check which security tools are installed"
```

You'll see a table like:

| Tool | Category | Status | Install Command |
|------|----------|--------|-----------------|
| `semgrep` | SAST | ✅ Installed | — |
| `bandit` | SAST (Python) | ✅ Installed | — |
| `trivy` | SCA / IaC / Container | ✅ Installed | — |
| `gitleaks` | Secret Scanning | ❌ Not installed | `brew install gitleaks` |
