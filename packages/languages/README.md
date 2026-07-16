# argus-languages

Built-in security scanner for **20+ languages and IaC formats** — pure Python, **no Semgrep, no Checkov, no extra installs**.

```bash
pip install argus-languages
argus-languages scan /path/to/your/project
```

Requires **Python 3.10+**.

---

## Quick start

```bash
pip install argus-languages

# Scan any supported project (auto-detects languages)
argus-languages scan /path/to/project

# JSON output
argus-languages scan /path/to/project --format json

# Scan a single file
argus-languages scan ./src/main.java
```

### Python API

```python
from argus_languages import scan_directory

result = scan_directory("/path/to/repo")
print(f"Findings: {len(result.findings)}")
for f in result.findings:
    print(f"[{f.severity}] {f.file}:{f.line} — {f.title}")
```

---

## Usage by language

Same command for every language — point at your project root or a specific file.

### JavaScript / TypeScript / Vue

```bash
argus-languages scan ./my-node-app
argus-languages scan ./src/components/Button.tsx
```

| Scans | `.js` `.jsx` `.ts` `.tsx` `.mjs` `.vue` |
| Checks | XSS, SQL injection patterns, eval/exec, weak crypto, hardcoded secrets, CORS wildcard, NoSQL injection |

> **React / Next.js projects:** use [argus-codescan](https://www.npmjs.com/package/argus-codescan) on npm instead — no Python needed.

---

### Python

```bash
argus-languages scan ./django-app
argus-languages scan ./api/main.py
```

| Scans | `.py` `.pyw` |
| Checks | Debug mode, hardcoded Flask secret, Django `ALLOWED_HOSTS = *`, SQL injection, pickle/yaml deserialization, command injection |

---

### Java / Kotlin / Scala

```bash
argus-languages scan ./spring-boot-app
argus-languages scan ./android-app/src/main/java
```

| Scans | `.java` `.jsp` `.kt` `.kts` `.scala` |
| Checks | SQL concatenation, XXE parsers, LDAP injection, path traversal, Spring CSRF disabled, log injection |

---

### PHP

```bash
argus-languages scan ./laravel-app
argus-languages scan ./public/index.php
```

| Scans | `.php` `.phtml` |
| Checks | XSS via `echo $_…`, LFI via `include($…)`, SQL injection, unsafe `unserialize()`, open redirects |

---

### Go

```bash
argus-languages scan ./cmd/api
argus-languages scan ./main.go
```

| Scans | `.go` |
| Checks | SQL via `fmt.Sprintf`, TLS `InsecureSkipVerify`, command injection |

---

### Ruby

```bash
argus-languages scan ./rails-app
```

| Scans | `.rb` `.erb` |
| Checks | Shell injection, mass assignment, command injection |

---

### C# / Rust / Swift / Scala / Perl / Lua / Elixir

```bash
argus-languages scan ./dotnet-api      # .cs
argus-languages scan ./rust-service    # .rs
argus-languages scan ./ios-app         # .swift
argus-languages scan ./elixir-app      # .ex .exs
```

| Language | Extensions | Example checks |
|----------|------------|----------------|
| C# | `.cs` | SQL concat, `BinaryFormatter` deserialization |
| Rust | `.rs` | `unsafe` blocks, shell via `Command` |
| Swift | `.swift` | Insecure credential storage |
| Perl | `.pl` `.pm` | Open with user input |
| Lua | `.lua` | `loadstring` / dynamic eval |
| Elixir | `.ex` `.exs` | `Code.eval_string` |

---

### Dart / Flutter (mobile)

```bash
argus-languages scan ./my-flutter-app
```

| Scans | `.dart` files, `pubspec.yaml`, `AndroidManifest.xml`, `Info.plist` |
| Checks | |

**Dart source (`.dart`):**
- Cleartext `http://` URLs
- Hardcoded API keys / tokens
- Weak MD5/SHA-1 hashing
- TLS validation disabled (`badCertificateCallback`)
- Sensitive data in `SharedPreferences`
- Unrestricted WebView JavaScript
- SQL concatenation in `rawQuery`

**Flutter config:**
- `android:debuggable="true"` in AndroidManifest
- Cleartext traffic / `allowBackup` / exported components
- iOS ATS disabled (`NSAllowsArbitraryLoads`)
- Hardcoded secrets in `pubspec.yaml`

Skips generated files: `*.g.dart`, `*.freezed.dart`.

---

### Terraform

```bash
argus-languages scan ./infra
argus-languages scan ./modules/vpc/main.tf
```

| Scans | `.tf` `.tfvars` `.hcl` |
| Checks | Public S3 ACLs, `0.0.0.0/0` security groups, unencrypted EBS, public RDS, hardcoded secrets, IAM wildcards, GCP/Azure public access |

---

### Ansible

```bash
argus-languages scan ./ansible
argus-languages scan ./playbooks/site.yml
```

| Scans | `.yml` / `.yaml` in `roles/`, `playbooks/`, `tasks/`, `handlers/`, etc. |
| Checks | Hardcoded passwords, SSL verify disabled, open file permissions (777), shell module usage, hardcoded tokens |

---

### Docker

```bash
argus-languages scan ./Dockerfile
argus-languages scan ./docker-compose.yml
```

| Scans | `Dockerfile`, `docker-compose.yml` / `.yaml` |
| Checks | Secrets in `ENV`, privileged mode, host network, docker socket mount, `:latest` tags |

---

### Kubernetes

```bash
argus-languages scan ./k8s
argus-languages scan ./manifests/deployment.yaml
```

| Scans | `.yaml` / `.yml` / `.json` with `apiVersion` + `kind` |
| Checks | Privileged containers, runAsUser 0, hostNetwork/hostPID, plaintext secrets, wildcard RBAC |

---

### Shell / SQL

```bash
argus-languages scan ./scripts/deploy.sh
argus-languages scan ./migrations/001_users.sql
```

| Scans | `.sh` `.bash` `.zsh` / `.sql` |
| Checks | curl piped to bash, unquoted variables / `GRANT ALL` / dynamic SQL exec |

---

## Monorepo / multi-language project

Scan the whole repo — all languages are detected automatically:

```bash
argus-languages scan .
```

Example: a repo with `frontend/` (JS), `backend/` (Java), and `infra/` (Terraform) is scanned in one command.

---

## Full Argus CLI (optional)

For CSV export, MCP, DAST, and external tools (Checkov, tfsec, ansible-lint):

```bash
pip install argus-scan
argus scan code /path/to/project --output ./report.csv
argus scan terraform /path/to/infra
argus scan all /path/to/project
```

---

## All supported languages

| Category | Languages / formats |
|----------|---------------------|
| Web & app | JavaScript, TypeScript, Python, Java, Kotlin, PHP, Go, Ruby, C#, Rust, Swift, Scala, Perl, Lua, Elixir, Vue, Dart |
| Mobile | Flutter (Dart + AndroidManifest + Info.plist + pubspec.yaml) |
| Infrastructure | Terraform, Ansible, Docker, Kubernetes |
| Other | Shell, SQL |

---

## Related packages

| Package | Install | Use case |
|---------|---------|----------|
| **argus-languages** | `pip install argus-languages` | This package — lightweight, all languages above |
| **argus-scan** | `pip install argus-scan` | Full CLI + MCP + DAST + Checkov/tfsec |
| **argus-codescan** | `npm install argus-codescan` | React / Next.js / Node only |

---

## License

MIT — see [GitHub](https://github.com/OkiriGabriel/argus-codescan-mcp).
