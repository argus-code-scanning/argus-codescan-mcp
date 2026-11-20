# GitHub Release v0.8.0 — copy/paste

## Release settings

- **Tag:** `v0.8.0`
- **Title:** `v0.8.0 — typosquat SCA, AI agent-rules prompt injection`

---

## Release notes

### Argus v0.8.0

Free and open source (MIT). Created by Okiri Gabriel.

#### New

- **Typosquat / hallucinated packages:** flag dependencies that look like popular names or that do not exist on the registry (AI-suggested packages). (#204)
- **AI agent rules prompt injection:** scan `AGENTS.md`, `.cursorrules`, Claude/Cursor/Windsurf rule files for invisible unicode, override instructions, secret exfil, and fetch-and-run patterns. (#205)

#### Fixes

- Windows CI: write agent-rules UTF-8 fixtures correctly. (#207)

## Install

```bash
pip install -U argus-scan          # pulls argus-languages>=0.7.0
npx argus-codescan@0.11.0 scan all . --fail-on high
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:0.8.0
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.8.0 |
| `argus-languages` (PyPI) | 0.7.0 |
| `argus-codescan` (npm) | 0.11.0 |
