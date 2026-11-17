# GitHub Release v0.10.0 — copy/paste

## Release settings

- **Tag:** `v0.10.0` (from `main`, after the version bump is merged)
- **Title:** `v0.10.0 — dependency checks for every language, script rules, accepted risks`

---

## Release notes

### Argus v0.10.0

Free and open source (MIT). Created by Okiri Gabriel.

#### Dependency vulnerabilities for every language (both packages)

- Built-in OSV check for **Go** (including the Go toolchain), **Flutter / Dart** (`pubspec.lock`), **Rust**, **Ruby**, **.NET**, **Python** (`poetry.lock`, `uv.lock`, `Pipfile.lock`), **PHP**, **Java** and **yarn / pnpm**. No extra tools needed; `--no-network` skips it. (#216, #218)
- **One finding per package**, with the version that fixes every advisory, **how the package gets into your project** (`via typeorm › tinyglobby › picomatch`) and the fix command for that ecosystem. (#215, #216)
- **Safe fix advice:** when npm's only "fix" is a downgrade (`npm audit fix --force`), Argus says there is no safe fix yet. (#215)
- **Dev-only** packages are lowered one level; a note explains npm audit's bigger "N vulnerabilities" count. (#214, #215)
- **Terraform:** unpinned git and registry modules, `http://` sources, providers without versions, missing `.terraform.lock.hcl`. (#217)

#### Accepted risks with an expiry date (both packages)

- `accepted_risks:` in `.argus.yml`: the finding stays in the report but doesn't fail `--fail-on` until the date; then it fails again. Notes when an entry expires soon, has expired, has no date, or matches nothing. The npm package now reads `.argus.yml` (`--policy <file>`). (#223)

#### New rules

- **Shell, PowerShell and batch scripts:** `eval "$1"`, unguarded `rm -rf "$DIR/"`, TLS checks off, `chmod 777`, passwords on the command line, sudoers edits, `Invoke-Expression $var`, plaintext passwords, firewall off, and more. Extensionless scripts are found by their `#!` line; `bin/` is scanned unless it holds build output. (#219, #220, #224)
- **ORM SQL injection:** TypeORM query builders, Knex `*Raw`, Prisma `*Unsafe`, `sequelize.literal`. (#213)

#### Fixes

- Table output keeps line numbers visible on long paths; Opengrep property injection on constant keys is low confidence. (#214)
- `Invoke-WebRequest -OutFile` is no longer reported as malware. (#224)

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.8.0
npx argus-codescan@0.12.0 scan all . --fail-on high
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:0.10.0
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.10.0 (requires `argus-languages>=0.8.0`) |
| `argus-languages` (PyPI) | 0.8.0 |
| `argus-codescan` (npm) | 0.12.0 (Node 20+) |
| Docker image (GHCR) | 0.10.0 |
