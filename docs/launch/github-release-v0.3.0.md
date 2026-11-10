# GitHub Release v0.3.0 — copy/paste

Use at: https://github.com/argus-code-scanning/argus-codescan-mcp/releases/new

- **Tag:** `v0.3.0` (create from `main`; pushing the tag publishes all three packages)
- **Title:** `v0.3.0 — Dependency CVEs across ecosystems, PHP/Laravel, privacy controls, local review`

---

## Release notes (paste below)

### Argus v0.3.0

**Argus** is a free, MIT-licensed security scanner: open-source tools behind one CLI and one MCP server for any IDE. This release covers everything merged since 0.2.1 (published Oct 10).

### ⚠️ Behaviour changes

- **npm CLI exit codes now follow `--fail-on`** (#107). With the default `never`, `argus-codescan scan …` / `review` exit 0 even when there are findings. If your CI relied on "exit 1 when anything is found", add `--fail-on low` (or your threshold).
- **New rule packs add findings** to `argus scan code` / `sast` / `all`: PHP, Laravel, Blade, `composer.json`, committed `.env` files, PII in logs, Python access control and JWT verification. A few are `high`/`critical`, so `--fail-on high` may start failing on real issues.
- **Fewer false positives**: PHP no longer gets the generic `sql-concat` / `command-injection` / `weak-crypto` rules (BookStack: 23,527 → 16 findings), and `pii-email-in-logs` no longer matches the word "email" in log text.

### What's new

#### Dependency CVEs (`argus scan sca`) (#99)
- npm: audits **every** project with a lockfile, one finding per advisory, marked `[runtime dependency]` / `[dev dependency]`
- Python: audits the project's `pyproject.toml` and requirements files (no longer the environment Argus runs in), severity from OSV
- **Go** via govulncheck: tells you whether your code actually **calls** the vulnerable function, with the call site
- **PHP** via `composer audit`, runtime vs dev

#### New code-scanning rules
- **PHP, Laravel, Blade, `composer.json`, `.env.production` / `.env.example`** (#100)
- **PII in logs, prints, exceptions and error trackers** (Sentry, Bugsnag, New Relic) for Python, JS/TS, Java, Go (#106, #74)
- **Python access control**: DRF `AllowAny`, empty `authentication_classes`, `@csrf_exempt`, Flask-Login disabled (#122)
- **JWT verification**: PyJWT, python-jose, jsonwebtoken, jjwt, golang-jwt: unverified decode, `none` algorithm, ignored expiry (#123, #124)
- **PCI-DSS** cardholder-data rules and `argus scan pci` / MCP `scan_pci` (#78, #93, #97)
- More malware rules: mining pools, `curl | bash` cradles (#73)
- Rules can carry `fix_guidance` and a data `classification`

#### Privacy and data handling
- Secret values echoed by scanners (e.g. Bandit's hardcoded-password message) are **redacted** in every report format (#94)
- Cloud upload strips git credentials and redacts emails, SSNs and card numbers (#96)
- `--no-persist` / `--artifacts-dir`: scanner temp files go to a private directory that is deleted after the run (#105)
- Findings carry `data_classification` (`pii`, `phi`, `pci`, `confidential`); filter with `--classification` (#102)
- Privacy & data-handling FAQ (#121)

#### Local review and CI
- `argus review` / MCP `review_code` (#84) and `argus-codescan review` for npm (#88): scan only changed or staged files; pre-commit example (#87)
- Pull requests scan only changed files (#86) and get a summary comment with fix suggestions (`argus ci pr-comment`, #101)

#### MCP
- `explain_finding` (#91), `get_fix_plan` (#89), and read-only resources for the finding schema and workflows (#90)

#### Other fixes
- Clear guidance when DAST/ZAP runs inside the Docker image (#95)
- Patched vulnerable npm transitive dependencies (#98)

```bash
pip install -U argus-scan          # pulls argus-languages 0.2.0
argus scan all . --fail-on high
npx argus-codescan@0.6.0 scan all . --fail-on high
```

#### Packages
| Package | Version |
|---------|---------|
| `argus-scan` (PyPI) | 0.3.0 (requires `argus-languages>=0.2.0`) |
| `argus-languages` (PyPI) | 0.2.0 |
| `argus-codescan` (npm) | 0.6.0 |

### Thank you, contributors 💙

@OpeyemiAdeniji, @daniyyell-dev, @kehindeadetule, @Holmes-R, @Architcybercrime, @xanforge, @RanaKhan77, @bonilokesh, @bongurishi, @8Ashwinee

### Contribute

New here? Start with the pinned [👋 Contributors welcome](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/103) issue. The access-control series (#120) and rule-quality issues (#108, #109) are open.

### Links

- Repo: https://github.com/argus-code-scanning/argus-codescan-mcp
- Privacy & data handling: `docs/privacy-and-data.md`

MIT licensed. Feedback and PRs welcome.

---

## Release checklist

1. Merge the release PR (version bumps) into `main` and wait for main's CI to be green
2. Push the tag from `main`: `git tag v0.3.0 && git push origin v0.3.0`
3. Watch the **Python CI** (Publish to PyPI, Publish argus-languages to PyPI) and **npm CI** (Publish to npm) runs for the tag
4. Confirm: `pip index versions argus-scan`, `pip index versions argus-languages`, `npm view argus-codescan version`
5. Create the GitHub Release from the tag with the notes above
