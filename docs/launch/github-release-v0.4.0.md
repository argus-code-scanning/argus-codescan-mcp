# GitHub Release v0.4.0 — copy/paste

## Release settings

- **Tag:** `v0.4.0` (create from `main`; pushing the tag publishes PyPI, npm, the VS Code extension and the Docker image)
- **Title:** `v0.4.0 — GitHub Actions, access control, SQL injection and LLM output rules`

---

## Release notes

### Argus v0.4.0

Free and open source (MIT). Created by Okiri Gabriel.

#### New rules (argus-languages 0.3.0)

- **GitHub Actions workflows**: `.github/workflows/*.yml` is now scanned. Rules cover script injection from untrusted `${{ github.* }}` context, `pull_request_target` and PR-head checkouts, actions and Docker images not pinned to a SHA or digest, and `write-all` permissions (#156, thanks @Architcybercrime)
- **Access control**: authentication, authorization or CSRF protection switched off in Django REST Framework, Flask-Login, Spring Security, ASP.NET, Rails, Laravel, Express CORS and NestJS (#128, #129)
- **SQL injection**: query strings built by concatenation, formatting or interpolation across languages; replaces the older `sql-concat` rule (#130)
- **Exposed endpoints**: Spring Boot Actuator exposing everything, the H2 console, Go `net/http/pprof`, Apollo introspection/playground and unauthenticated Express `/admin`, with a new `spring-config` file type (#131)
- **LLM output sinks**: model output passed to Python `eval`/`exec`, a shell, JavaScript `eval` or raw HTML (#155, thanks @Aaqibhafeezkhan)

#### Fixes and improvements

- `db-redis-keys-prod` now matches only Redis `KEYS` calls, not `dict.keys()` or `Object.keys()` (#154)
- `argus scan --fail-on` says when failing findings are hidden by `--classification` or `--min-severity` (#132)
- npm: `argus-codescan scan sca` finds every lockfile in a monorepo and separates runtime from dev dependencies (#133)
- Relative paths are POSIX on Windows, so path-based rules (such as Ansible) now match there

#### Project

- Contributors are assigned to an issue before opening a PR; an "Issue assignment" check enforces this (#158)
- argus-languages tests run on Linux, macOS and Windows in CI (#159)

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.3.0
npx argus-codescan@0.7.0 scan all . --fail-on high
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.4.0 (requires `argus-languages>=0.3.0`) |
| `argus-languages` (PyPI) | 0.3.0 |
| `argus-codescan` (npm) | 0.7.0 |
| VS Code extension `arestechub.argus-scan` | 0.1.0 (first Marketplace release) |

---

## Before tagging (one-time setup)

The v0.3.0 tag run could not publish, so these must be in place first:

1. **PyPI**: on pypi.org, open each of `argus-scan` and `argus-languages`, go to Publishing, and add a GitHub trusted publisher: owner `argus-code-scanning`, repository `argus-codescan-mcp`, workflow `ci-python.yml`, environment `pypi`.
2. **npm**: on npmjs.com, open `argus-codescan`, then Settings, then Trusted publisher, and choose GitHub Actions: organization `argus-code-scanning`, repository `argus-codescan-mcp`, workflow `ci-npm.yml`, environment `npm`. Alternatively, add an `NPM_TOKEN` secret.
3. **VS Code Marketplace**: add a `VSCE_PAT` secret (an Azure DevOps token with the Marketplace "Manage" scope for publisher `arestechub`). Optionally add `OVSX_PAT` to also publish to Open VSX for Cursor and VSCodium.

Then push the tag from `main`: `git tag v0.4.0 && git push origin v0.4.0`
