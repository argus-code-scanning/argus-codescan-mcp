# Using Argus by language

Two ways to run Argus:

| | Install | Best for |
|---|---|---|
| **Python package** (`argus-scan`) | `pip install argus-scan` (Python 3.10+) | Every language, malware and supply-chain checks, IaC, containers, the MCP server |
| **npm package** (`argus-codescan`) | `npx argus-codescan …` (no Python needed) | Node / React / Next.js projects, plus Java/Kotlin, Python, PHP, Go source rules |

Commands that work everywhere:

```bash
argus scan all .                         # everything that applies to the project
argus scan all . --fail-on high          # exit 1 on high/critical findings (CI)
argus scan all . --format sarif -o argus.sarif   # GitHub code scanning
argus review .                           # only files changed vs HEAD (add --staged before a commit)
```

**Built in** below means it works right after install. **Optional** means Argus uses the tool if it is on your PATH and skips it otherwise; the report lists what was skipped.

Online lookups (OSV) send only package names and versions. Use `--no-network` to turn them off.

---

## Java

```bash
pip install argus-scan
argus scan all .
argus scan sca .        # dependencies only
argus scan sast .       # source code only
```

| Check | What it finds | Built in / optional |
|---|---|---|
| Source code | SQL built from strings (JDBC, `Statement`, string concatenation), XXE, LDAP injection, path traversal, unsafe deserialization, command injection (`Runtime.exec` / `ProcessBuilder` with input), JJWT tokens parsed without a signature, log injection, PII in logs | Built in |
| Spring Security | `anyRequest().permitAll()` / `"/**"` permitted, `web.ignoring()` of everything, CSRF disabled, `@PermitAll` | Built in |
| Spring Boot config | `application*.properties` / `*.yml`: Actuator exposing every endpoint, H2 console enabled | Built in |
| JSP | Web shells (`Runtime.exec` / `ProcessBuilder` in `.jsp` pages) | Built in |
| Dependencies (CVEs) | Reads `pom.xml` (resolves `${properties}`), `gradle.lockfile`, `build.gradle(.kts)`, `libs.versions.toml`; reports the CVE, severity and nearest fixed version from OSV | Built in (Trivy is used instead when installed) |
| Known-malicious packages | Same files, checked against OSV `MAL-` records | Built in |
| More rules | Semgrep's Java rules | Optional: `pip install semgrep` |
| Secrets | Keys and passwords in `.java`, `.properties`, `.yml` | Optional: gitleaks / TruffleHog |

With npm only: `npx argus-codescan scan sast .` runs the same Java, Spring and JSP source rules. Dependencies need the Python package.

## Kotlin

Same as Java: the Java rules also cover `.kt` / `.kts`, Kotlin SQL string templates (`"… WHERE id = ${id}"`), Gradle Kotlin DSL (`build.gradle.kts`) and version catalogs.

```bash
pip install argus-scan && argus scan all .
# or, source rules only:
npx argus-codescan scan sast .
```

## Python

```bash
pip install argus-scan
argus scan all .
```

| Check | What it finds | Built in / optional |
|---|---|---|
| Source code | SQL injection, command injection (`os.system`, `shell=True`), `eval`/`exec`, unsafe deserialization (`pickle`, `yaml.load`), path traversal, SSRF, weak crypto, hardcoded secrets, Django/DRF/Flask auth switched off | Built in |
| AI / ML | Unsafe model loading (`torch.load`, `pickle`, `trust_remote_code`), LLM output passed to `eval`/shell/HTML, hardcoded LLM keys | Built in (`argus scan ml .`) |
| Dependencies (CVEs) | `requirements*.txt`, `pyproject.toml`, `poetry.lock` | Optional: `pip install pip-audit safety` (or Trivy) |
| Known-malicious packages | Pinned `requirements*.txt`, `poetry.lock`, `uv.lock` against OSV `MAL-` | Built in |
| Remote dependency sources | Dependencies installed from plain HTTP, archives or unpinned git | Built in |
| More rules | Bandit, Semgrep | Optional: `pip install bandit semgrep` |

## Node.js, JavaScript, TypeScript (npm, yarn, pnpm)

No Python needed:

```bash
npx argus-codescan scan all .            # dependencies + source + secrets, writes a CSV report
npx argus-codescan scan all . --fail-on high --no-csv
npx argus-codescan review --staged       # before a commit
```

| Check | What it finds | Package |
|---|---|---|
| Dependencies (CVEs) | `npm audit` in every project of a monorepo, split into runtime and dev, with the installed version | npm and Python |
| Source code | `eval`, SQL built from variables, command injection, XSS (`innerHTML`, `dangerouslySetInnerHTML`), NoSQL injection, SSRF, path traversal, weak crypto, hardcoded secrets | npm and Python |
| ESLint security rules + Opengrep | Extra JS/TS rules; Opengrep downloads itself on first use | npm |
| Known-malicious packages | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` against OSV `MAL-` | Python (`argus scan sca .`) |
| Install-script malware | `postinstall` / `preinstall` hooks that download and run code, run inline code or decode payloads | Python (`argus scan malware .`) |
| Worm behaviour | Credential harvesting plus exfiltration, package code that runs `npm publish`, obfuscated JS, crypto-wallet hijacking, clipboard address swappers, permit-phishing drainers | Python (`argus scan malware .`) |
| Known threats | URLs, domains, IPs and file hashes from abuse.ch feeds and your own `.argus/iocs.txt` | Python (`argus scan threats .`) |

For a Node project, the best coverage is both: `npx argus-codescan scan all .` in CI, plus `pip install argus-scan && argus scan malware . && argus scan sca .` for the supply-chain checks.

## PHP and Laravel

```bash
pip install argus-scan
argus scan all .
```

| Check | What it finds | Built in / optional |
|---|---|---|
| Source code | SQL injection (`mysql_query`, string-built SQL), command injection (`system`, `exec`, `shell_exec`, backticks), `eval`, `unserialize`, file inclusion, path traversal, XSS (`echo $_GET`), SSRF, open redirects, weak password hashing, `phpinfo()` / `display_errors` left on | Built in |
| Laravel | Raw queries with request input, mass assignment (`$request->all()`, empty `$guarded`), unescaped Blade `{!! !!}`, routes without auth middleware, CSRF disabled, debug mode on in production, insecure session cookies, a real `APP_KEY` committed, open redirects | Built in |
| `composer.json` | TLS or `secure-http` disabled, plain-HTTP repositories, all plugins allowed, scripts that download and run code, `minimum-stability: dev` | Built in |
| Dependencies (CVEs) | `composer audit` | Optional: Composer on PATH |
| Known-malicious packages | `composer.lock` against OSV `MAL-` | Built in |
| Web shells | `eval($_GET…)`, `system($_POST…)` and similar | Built in (`argus scan malware .`) |

With npm only: `npx argus-codescan scan sast .` runs basic PHP rules.

## Go

```bash
pip install argus-scan
argus scan all .
```

Built in: insecure TLS (`InsecureSkipVerify`), SQL built with `fmt.Sprintf`, command injection (`exec.Command("sh", "-c", …)`), `net/http/pprof` exposed, JWT `none` / unverified parsing. Dependencies: optional `govulncheck` (`go install golang.org/x/vuln/cmd/govulncheck@latest`).

## Ruby / Rails, C# / .NET, Rust, Dart / Flutter

```bash
pip install argus-scan
argus scan all .
```

| Language | Built in | Dependencies |
|---|---|---|
| Ruby / Rails | Command injection (`system`, backticks with `#{}`), `skip_before_action :authenticate`, CSRF disabled, `null_session` | Optional: Trivy (`Gemfile.lock`) |
| C# / .NET | `[AllowAnonymous]`, `.AllowAnonymous()`, Entity Framework raw SQL, `Process.Start("cmd", … + input)` | Optional: Trivy |
| Rust | `unsafe` blocks (review) | Optional: Trivy (`Cargo.lock`) |
| Dart / Flutter | Hardcoded secrets, cleartext HTTP, SQL concatenation, weak hashing, certificate checks disabled, insecure storage; Android `debuggable` / `allowBackup` / exported components, iOS arbitrary loads | Optional: Trivy |

## Infrastructure, CI and containers

```bash
argus scan iac .                 # Terraform, Kubernetes, Dockerfiles, CloudFormation
argus scan terraform .
argus scan ansible .
argus scan container nginx:1.25  # image CVEs (needs Trivy)
argus scan dast https://staging.example.com   # live site (needs OWASP ZAP or Nikto)
```

| Target | Built in | Optional |
|---|---|---|
| Terraform | Public S3 / GCS / Azure storage, open security groups, public RDS, IAM `*` wildcards, unencrypted EBS, hardcoded secrets, HTTP state backends | Checkov, Trivy, tfsec, tflint, KICS |
| Ansible | Hardcoded secrets and `become` passwords, `shell`/`command` with variables, SSL verification off, world-writable permissions, insecure git checkouts | ansible-lint, KICS, Checkov |
| Dockerfile / Kubernetes | Secrets in `ENV`, privileged containers, host network / PID, Docker socket mounts, running as root | Checkov, Trivy |
| GitHub Actions | Script injection from PR titles/branches, `pull_request_target` with a PR checkout, actions not pinned to a SHA, `write-all` permissions; injected payloads: `toJSON(secrets)` dumps, secrets piped to curl/base64, encoded payloads, crypto miners, self-hosted runners on pull requests | — |

---

## Cutting false positives

- `argus-ignore[rule-id]: reason` on a line, or on the line above, suppresses one finding (a reason is required).
- Findings in `tests/`, `fixtures/`, `docs/`, `examples/` and minified files are lowered one severity level.
- Low-confidence rules are reported but don't fail `--fail-on` unless you add `--fail-on-low-confidence`.
- Malware rules are exempt from all three.

See the [README](../README.md#cutting-false-positives) for details.
