# GitHub Release v0.5.0 — copy/paste

## Release settings

- **Tag:** `v0.5.0` (from `main`; pushing the tag builds the Docker image and, once publishing is configured, PyPI / npm / VS Code)
- **Title:** `v0.5.0 — far fewer false positives, obfuscated-JS and wallet-hijack detection`

v0.4.0 was tagged but only reached the Docker registry, so these notes cover everything since v0.3.0.

---

## Release notes

### Argus v0.5.0

Free and open source (MIT). Created by Okiri Gabriel.

#### Far fewer false positives

- **Ignore one finding in the code:** add `argus-ignore[rule-id]: reason` on the line or the line above. A reason is required, and every suppression is listed in the report.
- **Tests, docs and bundles count less:** findings in `tests/`, fixtures, `docs/`, `examples/`, test files (`test_*.py`, `*.spec.ts`, …) and minified bundles are lowered one severity level and labelled.
- **Confidence levels:** rules that only flag a risky API (e.g. `knex.raw()`, `[AllowAnonymous]`, `unsafe {}`) are low confidence. They're still shown but don't fail `--fail-on` unless you add `--fail-on-low-confidence` (or `fail_on_low_confidence: true` in `.argus.yml`).
- **Malware rules can't be silenced:** scanned code can't hide malware with an ignore comment or by sitting in a test folder.
- Builds that would fail at `--fail-on high` dropped by about 75% (Python package) and 94% (npm package) on our own codebase.
- Works the same in `argus-scan` (Python) and `argus-codescan` (npm).

#### New detection

- **Obfuscated JavaScript and crypto-wallet hijacking**: javascript-obfuscator output, encoded `eval` payloads, character-code chains, `window.ethereum` and fetch/XHR hooks, and the hook-plus-address-regex combination used in the Sept 2025 chalk/debug npm compromise (#157, thanks @Architcybercrime)
- **GitHub Actions workflows**: script injection, `pull_request_target` and PR-head checkouts, unpinned actions and Docker images, `write-all` permissions (#156, thanks @Architcybercrime)
- **Access control**: authentication, authorization or CSRF switched off in Django REST Framework, Flask-Login, Spring Security, ASP.NET Core, Rails, Laravel, Express and NestJS (#128, #129)
- **SQL injection**: queries built from variables in Python, JS/TS, Java, Kotlin and Go (#130)
- **Exposed endpoints**: Spring Boot Actuator, H2 console, Go pprof, Apollo playground/introspection, unauthenticated Express `/admin` (#131)
- **LLM output sinks**: model output passed to `eval`/`exec`, a shell, JS `eval` or raw HTML (#155, thanks @Aaqibhafeezkhan)

#### Fixes and improvements

- npm: `scan sca` audits every project in a monorepo and separates runtime from dev dependencies (#133)
- npm: the eval rule no longer flags method calls like `regex.exec()` (#165)
- `--fail-on` explains failures caused by findings your filters hid (#132)
- Redis `KEYS` rule matches only Redis calls (#154)
- Path-based rules now work on Windows
- Docker image at `ghcr.io/argus-code-scanning/argus-codescan-mcp` with version tags

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.4.0
npx argus-codescan@0.8.0 scan all . --fail-on high
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:0.5.0
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.5.0 (requires `argus-languages>=0.4.0`) |
| `argus-languages` (PyPI) | 0.4.0 |
| `argus-codescan` (npm) | 0.8.0 |
| Docker image | 0.5.0 |
