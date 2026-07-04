# argus-codescan (npm)

Security scanner that **ships with everything built in** — works on **Windows, macOS, and Linux**. No Homebrew, no Python, no manual tool installs.

```bash
npm install -D argus-codescan
npx argus-codescan scan all .
```

## What runs automatically (bundled)

| Scanner | What it checks |
|---------|----------------|
| **argus-native** | Source code in Python, Java, PHP, JS, TS, Go — SQLi, XSS, injection, weak crypto |
| **eslint-security** | JavaScript / JSX security rules + unused variables |
| **argus-secrets** | Hardcoded API keys, passwords, private keys |
| **npm audit** | Dependency vulnerabilities |

## Commands

```bash
argus-codescan scan sca .      # dependencies only
argus-codescan scan sast .     # source code (all languages above)
argus-codescan scan secrets .  # credentials
argus-codescan scan all .      # everything
argus-codescan tools           # show what's included
```

## React / Node project setup

```json
{
  "scripts": {
    "security:all": "argus-codescan scan all . --fail-on high"
  }
}
```

## Optional (not required)

- **Semgrep** — deeper rules if `pip install semgrep` (optional, any OS)
- **Gitleaks** — deeper secrets if installed from GitHub releases

The package works fully without these.

## Full Python suite (Terraform, DAST, Ansible…)

```bash
pip install argus-scan
argus scan all /path/to/project
```
