# Trusted publishing setup (clear the red Deployments)

Tag pushes (`v*`) publish via GitHub Environments: **pypi**, **npm**, **vscode-marketplace**.  
The sidebar shows ✗ when the **last CI attempt** failed — even if you published manually.

Do these once. No need to put long-lived tokens in git.

---

## 1. PyPI (OIDC) — `argus-scan` + `argus-languages`

`argus-languages` may already work; **`argus-scan` needs its own trusted publisher**.

For **each** of:

- https://pypi.org/manage/project/argus-scan/settings/publishing/
- https://pypi.org/manage/project/argus-languages/settings/publishing/

Add a **GitHub** publisher:

| Field | Value |
|-------|--------|
| Owner | `argus-code-scanning` |
| Repository | `argus-codescan-mcp` |
| Workflow | `ci-python.yml` |
| Environment | `pypi` |

Save. No PyPI API token required for CI after this.

Workflow jobs: `Publish argus-languages to PyPI` then `Publish to PyPI` (both use `environment: pypi` + `id-token: write`).

---

## 2. npm (OIDC) — `argus-codescan`

1. Open https://www.npmjs.com/package/argus-codescan/access  
   (or **Package settings → Trusted publisher**)
2. Add **GitHub Actions**:

| Field | Value |
|-------|--------|
| Organization / user | `argus-code-scanning` |
| Repository | `argus-codescan-mcp` |
| Workflow | `ci-npm.yml` |
| Environment | `npm` |

Requires **npm ≥ 11.5.1** on the runner (workflow installs `npm@11`).

**Optional fallback:** create an automation token on npmjs.com and add repo/env secret `NPM_TOKEN` (environment **npm**). Prefer OIDC; leave `NPM_TOKEN` unset when trusted publishing works.

---

## 3. VS Code Marketplace — `VSCE_PAT`

1. Azure DevOps → User settings → **Personal access tokens**
2. Create a PAT with **Marketplace → Manage** for publisher `arestechub`
3. In GitHub:  
   **Settings → Environments → `vscode-marketplace` → Environment secrets**  
   Add `VSCE_PAT` = that token  
4. Optional: `OVSX_PAT` for Open VSX (Cursor / VSCodium)

Until `VSCE_PAT` is set, the publish job **skips** Marketplace upload (no fake failure).

---

## 4. github-pages

The ✗ is an **old** deployment (often from before the org move). Current `pages.yml` only deploys when `website/package-lock.json` exists.

To quiet the sidebar later: ship a `website/` or ignore this environment until then.

---

## Verify after setup

```bash
# bump versions, merge, then:
git tag vX.Y.Z && git push origin vX.Y.Z
gh run list --branch vX.Y.Z
```

Expect green **Publish to PyPI**, **Publish to npm**, and (if PAT set) **Publish to VS Code Marketplace**.

Manual publish still works anytime:

```bash
cd packages/languages && uv publish
cd ../python && uv publish
cd ../npm && npm publish --access public
```
