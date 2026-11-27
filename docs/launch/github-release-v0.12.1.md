# GitHub Release v0.12.1 — copy/paste

- **Tag:** `v0.12.1` (from `main`, after this bump is merged)
- **Title:** `v0.12.1: PR scans respect .argus.yml`

---

### Argus v0.12.1

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.12.1 |
| `argus-languages` (PyPI) | 0.10.1 |
| `argus-codescan` (npm) | 0.14.1 |

- **Fix:** PR scans (`--paths-file`, used by the GitHub Action and the PR comment) now apply `.argus.yml` `exclude_paths` and suppressions. Findings said `server.py` instead of the full path, so `tests/**` and `**/app/server.py` never matched and already-reviewed findings showed up on every PR. (#280)
- Support links: Buy Me a Coffee on the npm, PyPI and VS Code pages and a Sponsor button on GitHub. Nothing changes in scan output. (#281)

---

## Publish

```bash
git checkout main && git pull
python3 scripts/versions.py show
git tag v0.12.1 && git push origin v0.12.1
```

CI publishes argus-languages, argus-scan, argus-codescan and the Docker image. argus-scan needs a PyPI trusted publisher (workflow `ci-python.yml`, environment `pypi`); without it, publish argus-scan by hand from `packages/python`.
