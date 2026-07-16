# argus-codescan

Security scanner for **React, Next.js, and Node.js** projects. Works on **Windows, macOS, and Linux** — no Python, no Homebrew, no manual installs.

```bash
npm install -D argus-codescan
npx argus-codescan scan all .
```

npm: https://www.npmjs.com/package/argus-codescan

---

## Install

```bash
# In your project
npm install -D argus-codescan

# Or run without adding to package.json
npx argus-codescan scan all .
```

Requires **Node.js 18+**.

---

## Quick start

```bash
npx argus-codescan scan sca .       # dependency vulnerabilities
npx argus-codescan scan sast .      # source code (JS/TS/JSX)
npx argus-codescan scan secrets .   # leaked API keys & tokens
npx argus-codescan scan all .       # everything above
npx argus-codescan tools            # show what's bundled
```

Every scan **writes a CSV report** automatically to your working directory.

---

## Usage by scan type

### SCA — dependency scan (`scan sca`)

Check `package.json` dependencies for known CVEs (uses npm audit).

```bash
npx argus-codescan scan sca .
npx argus-codescan scan sca . --output ./reports/deps.csv
```

**Finds:** vulnerable packages (e.g. js-yaml, next, postcss, transitive deps).

---

### SAST — source code scan (`scan sast`)

Scan your JavaScript / TypeScript / JSX / TSX source files.

```bash
npx argus-codescan scan sast .
npx argus-codescan scan sast ./src --fail-on high
```

**Runs automatically (no extra install):**

| Scanner | What it checks |
|---------|----------------|
| **argus-native** | SQL injection patterns, XSS, eval/exec, weak crypto, hardcoded secrets, CORS |
| **eslint-security** | Unsafe regex, child_process, eval, prototype issues in JS/JSX |
| **opengrep** | Auto-downloads on first scan (Semgrep-compatible deep rules, no pip) |

**File types:** `.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs`

---

### Secrets scan (`scan secrets`)

Find hardcoded credentials in your codebase.

```bash
npx argus-codescan scan secrets .
npx argus-codescan scan secrets . --output ./reports/secrets.csv
```

**Finds:** API keys, AWS keys, private keys, passwords, tokens in source files.

---

### Full scan (`scan all`)

Run SCA + SAST + secrets in one command.

```bash
npx argus-codescan scan all .
npx argus-codescan scan all . --fail-on high --output ./reports/full.csv
```

---

## React / Next.js project setup

Add to `package.json`:

```json
{
  "devDependencies": {
    "argus-codescan": "^0.4.4"
  },
  "scripts": {
    "security:scan": "argus-codescan scan sca . --output ./reports/deps.csv",
    "security:code": "argus-codescan scan sast . --output ./reports/code.csv",
    "security:secrets": "argus-codescan scan secrets . --output ./reports/secrets.csv",
    "security:all": "argus-codescan scan all . --output ./reports/full.csv"
  }
}
```

Run:

```bash
npm run security:scan      # dependencies only
npm run security:code      # source code only
npm run security:all       # full audit
```

Add `reports/` to `.gitignore` if you don't want CSV files committed.

---

## CLI options

| Option | Description |
|--------|-------------|
| `--output`, `-o FILE` | CSV output path (default: `argus-<type>-<timestamp>.csv`) |
| `--no-csv` | Skip writing CSV file |
| `--format json` | Print JSON to terminal instead of table |
| `--format csv` | Print CSV to terminal |
| `--fail-on high` | Exit code 1 if high+ findings (for CI/CD) |

Examples:

```bash
npx argus-codescan scan all . --format json
npx argus-codescan scan sast . --no-csv
npx argus-codescan scan sca . --fail-on moderate
```

---

## CI/CD (GitHub Actions)

```yaml
- name: Security scan
  run: |
    npm install
    npx argus-codescan scan all . --fail-on high --output ./reports/security.csv
```

---

## MCP server (optional — for Cursor / Claude)

For AI-assisted scanning, use the Python MCP server:

```bash
pip install argus-scan
argus mcp
```

Or configure Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "argus": { "command": "uvx", "args": ["argus-scan", "mcp"] }
  }
}
```

The **npm package** is for direct CLI scanning in Node projects — no MCP required.

---

## Java, PHP, Flutter, Terraform, Ansible?

This npm package is for **Node / React / Next.js only**.

For other languages, use the Python package:

```bash
pip install argus-languages
argus-languages scan /path/to/flutter-app
argus-languages scan /path/to/terraform
```

Full suite with MCP:

```bash
pip install argus-scan
argus scan code /path/to/project
```

---

## Optional enhancements (not required)

| Tool | Install | Adds |
|------|---------|------|
| **Gitleaks** | [gitleaks.io](https://github.com/gitleaks/gitleaks) | Deeper secret scanning |
| **semgrep** | `pip install semgrep` | Used instead of opengrep if on PATH |

Everything works without these — opengrep auto-downloads on first SAST scan.

---

## Related packages

| Package | Install | Best for |
|---------|---------|----------|
| **argus-codescan** | `npm install argus-codescan` | React, Next.js, Node.js |
| **argus-languages** | `pip install argus-languages` | Java, PHP, Flutter, Terraform, Ansible |
| **argus-scan** | `pip install argus-scan` | Full CLI + MCP + DAST |

---

## License

MIT — see [GitHub](https://github.com/OkiriGabriel/argus-codescan-mcp).
