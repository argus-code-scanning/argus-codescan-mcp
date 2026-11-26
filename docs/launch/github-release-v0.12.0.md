# GitHub Release v0.12.0 — copy/paste

## Release settings

- **Tag:** `v0.12.0` (from `main`, after the version bump is merged)
- **Title:** `v0.12.0: launch check and test check for apps built with AI tools`

---

## Release notes

### Argus v0.12.0

Free and open source (MIT). Created by Okiri Gabriel.

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.12.0 |
| `argus-languages` (PyPI) | 0.10.0 |
| `argus-codescan` (npm) | 0.14.0 |

#### Apps built with AI tools

- **`argus scan vibe`** (MCP `scan_vibe`, `npx argus-codescan scan vibe`) is a launch check for apps built with Cursor, Claude Code, Lovable, Bolt, v0 or Replit. It covers:
  - Supabase tables without Row Level Security, and policies of `(true)`;
  - open or test-mode Firebase rules;
  - secret keys in `NEXT_PUBLIC_` / `VITE_` variables, and the `service_role` key in browser code;
  - `dangerouslyAllowBrowser: true`;
  - routes and server actions that change data without an auth check;
  - secrets, headers, rate limiting, hallucinated packages and cookies.

  The report gives a 0–100 safety score, a plain fix for each problem, and a prompt to paste into your AI tool. Secret values are masked in every prompt. (#272, #273)
- **`argus unit-test`** (MCP `check_unit_tests`, `npx argus-codescan unit-test`) checks whether the app is tested. It reports:
  - no test runner, or the placeholder `npm test` script;
  - routes that change data and have no test;
  - tests with no assertions;
  - `.only` or `.skip` left in;
  - CI that never runs the tests;
  - no end-to-end test for login or checkout.

  You get a 0–100 testing score and a prompt that writes the missing tests. `--fail-under` gates CI. (#276)

#### New rules

- Prototype pollution in JavaScript / TypeScript. (#188)
- Request input in response and email headers (header and email injection). (#187)
- XPath injection in 5 languages. (#264)
- Unbounded LLM consumption: no max tokens, no rate limit. (#253)
- SQL injection across lines in JavaScript / TypeScript, following user input through variables with tree-sitter. (#183)

#### Sharing reports

- **`sanitize_report`** (MCP) produces a copy of a report that is safe to paste into an AI chat or a ticket. It masks personal data and secret values, can hash file paths, and can keep only the top findings. (#59)

#### Fixes

- The `rm -rf` rule and the email redaction pattern now run in linear time on hostile input. (#265)
- Go, govulncheck and Composer versions are pinned in the Docker image. (#268)
- **npm:**
  - `--fail-on medium` now fails as it should, and unknown values are rejected. (#261)
  - JSON output piped to another program is no longer cut off at 64 KB.

---

## Publish (after the release PR is merged)

Pushing a `v*` tag publishes everything from CI: argus-languages, then argus-scan to PyPI (trusted publishing), argus-codescan to npm (with provenance), and the Docker image. Don't also run `uv publish` / `npm publish` by hand.

```bash
git checkout main && git pull
python3 scripts/versions.py show
git tag v0.12.0 && git push origin v0.12.0
```

Run these from the repo root. `versions.py show` must print the new versions before you tag: a tag on a commit without the bump starts the publish jobs on the old code.
