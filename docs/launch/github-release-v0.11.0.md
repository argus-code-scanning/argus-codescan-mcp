# GitHub Release v0.11.0 — copy/paste

## Release settings

- **Tag:** `v0.11.0` (from `main`, after the version bump is merged)
- **Title:** `v0.11.0 — privacy and PII scans, GitHub Action, batch fixes, redaction`

---

## Release notes

### Argus v0.11.0

Free and open source (MIT). Created by Okiri Gabriel.

#### Privacy and personal data

- **`argus scan pii`** (MCP `scan_pii`): real-looking emails, phone numbers, US SSNs, UK National Insurance numbers, names and street addresses hardcoded in code, config and fixtures (JSON/YAML/CSV/.env/SQL), PII in logs, and Luhn-valid card numbers. Example and test values are ignored; in tests only ID numbers are reported. (#52)
- **`argus scan privacy`** (MCP `scan_privacy`): GDPR/CCPA code patterns — trackers with no consent mechanism, no account deletion or data export, Prisma models with no retention field, fingerprinting, non-EU storage. Code patterns, not a legal assessment. (#55)
- **Redaction:** personal data is masked in SARIF, MCP responses and cloud uploads by default; `--redact-pii` / `--no-redact-pii` and `data_policy` in `.argus.yml` (`redact_pii`, `max_snippet_lines`, `exclude_fields`). Stable tags with `ARGUS_REDACTION_KEY`. (#53, #54)

#### Fixing findings

- **GitHub Actions auto-fixes:** `apply_fix` pins `uses:` to a commit SHA and moves `${{ github.* }}` out of `run:` into `env:`. (#234)
- **`apply_fixes`** (MCP): preview every fixable finding as one diff, apply after one confirmation; refuses if a file changed since the preview. (#40)
- **VS Code 0.2.0:** *Ask AI to fix* copies a ready prompt (finding + nearby code; never secrets) and opens your AI chat. (#31)

#### CI

- **GitHub Action:** `uses: argus-code-scanning/argus-codescan-mcp@v1` — scan, fail at a threshold, job summary, SARIF to the Security tab. (#37)
- Examples: **nightly scan** that keeps one issue for new critical findings (#35), **GitLab CI** template with MR Code Quality widget and summary note (#41).

#### New rules and checks

- **Insecure cookie flags** (Express, Flask/Django, Java/Spring, PHP, ASP.NET). (#197)
- **Missing or disabled HTTP security headers** (project-level, 15+ frameworks). (#198)
- **Luhn-valid card numbers hardcoded in source**; PCI-DSS scan included in `scan all`. (#240, #242)

#### Fixes and internals

- **`--min-severity` no longer hides failing findings from `--fail-on`** (`--min-severity critical --fail-on high` passed builds with a high finding). (#12)
- Scan plugins: installed packages can add `argus scan <name>` (`argus.scan_plugins` entry point). (#238)
- Integration tests for the CLI and MCP server; `scripts/versions.py` keeps package versions in sync; prompt cookbook expanded. (#12, #11, #39)

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.9.0
argus scan pii .
argus scan privacy .
```

| Package | Version | Install |
|---|---|---|
| `argus-scan` (CLI + MCP) | 0.11.0 | `pip install argus-scan==0.11.0` (needs `argus-languages>=0.9.0`) |
| `argus-languages` (built-in rules) | 0.9.0 | `pip install argus-languages==0.9.0` |
| `argus-codescan` (npm) | 0.12.1 | `npx argus-codescan@0.12.1` |
| VS Code extension | 0.2.0 | Marketplace: `arestechub.argus-scan` |
