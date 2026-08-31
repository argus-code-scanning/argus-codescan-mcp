# Wiz integration guide

How to use **Argus** alongside **Wiz** code scanning (Wiz CLI + Wiz Cloud / UVM).

Argus and Wiz solve overlapping but different problems:

| | **Argus** | **Wiz CLI / Wiz Code** |
|---|-----------|-------------------------|
| **Model** | Open-source local orchestrator (20+ tools) | Wiz platform scanner + cloud graph |
| **Strength** | MIT, no vendor lock-in, MCP for IDEs, SARIF for GitHub | Policy in Wiz, cloud correlation, dev policies at scale |
| **Output** | Unified CLI/MCP report, SARIF, JSON | Native upload to Wiz dashboard |
| **Cost** | Free (scanner tools + optional AI client) | Wiz subscription |

**Recommended:** run both in CI — Wiz for platform-native findings and cloud context; Argus for extra open-source coverage and IDE/MCP workflows. Optionally **ingest Argus SARIF into Wiz UVM** so everything appears in one Wiz view.

---

## Prerequisites (Wiz side)

1. **Wiz Code / UVM** enabled on your tenant (required for external scanner ingestion).
2. **Service account** (Settings → Service Accounts → Custom Integration / GraphQL API):
   - `create:external_data_ingestion`
   - `read:resources`
   - `read:projects`
   - `read:sast_findings` (if reading back from Wiz)
3. **Secrets** (GitHub / CI):
   - `WIZ_CLIENT_ID`
   - `WIZ_CLIENT_SECRET`
   - `WIZ_TOKEN_URL` — typically `https://auth.app.wiz.io/oauth/token`
   - `WIZ_API_ENDPOINT_URL` — e.g. `https://api.us1.app.wiz.io/graphql` (region-specific)

---

## Pattern 1 — Parallel scans (simplest)

Run **Wiz CLI** and **Argus** in the same pipeline. Each uploads/displays results in its native channel.

```yaml
# .github/workflows/code-security.yml (excerpt)
jobs:
  wiz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Wiz CLI auth
        run: |
          curl -o wizcli https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64
          chmod +x wizcli
          ./wizcli auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET"
        env:
          WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
          WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
      - name: Wiz directory scan (code + secrets)
        run: ./wizcli dir scan --path . --name "${{ github.repository }}-${{ github.sha }}"
      - name: Wiz IaC scan
        run: ./wizcli iac scan --path . --name "${{ github.repository }}-iac-${{ github.sha }}"

  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install argus-scan   # or pip install -e packages/python
      - run: argus scan all . --format sarif -o argus.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: argus.sarif
          category: argus
```

**When to use:** You want Wiz policies and cloud graph immediately, plus Argus/GitHub Code Scanning without building a custom upload layer.

---

## Pattern 2 — Argus → Wiz UVM (SARIF ingestion)

Wiz does not take raw SARIF via a single “upload file” button; third-party findings enter through the **external data ingestion** GraphQL API. Convert SARIF → Wiz ingestion JSON, then POST.

### Step 1 — Generate SARIF from Argus

```bash
argus scan all . --format sarif -o argus.sarif --fail-on never
# or focused scans:
argus scan code .
argus scan ml .
argus scan secrets .
```

### Step 2 — Convert & upload

Use the community converter (validates schemas, CI-ready):

```yaml
- name: Argus scan → SARIF
  run: argus scan all . --format sarif -o sarif/argus.sarif

- name: Ingest Argus SARIF into Wiz
  uses: gassorg/wiz-sarif-action-ingest/.github/workflows/action.yml@main
  with:
    sarif_input_dir: "./sarif"
    repository_name: ${{ github.repository }}
    repository_url: ${{ github.server_url }}/${{ github.repository }}
    branch_name: ${{ github.ref_name }}
  secrets:
    WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
    WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
    WIZ_TOKEN_URL: ${{ secrets.WIZ_TOKEN_URL }}
    WIZ_API_ENDPOINT_URL: ${{ secrets.WIZ_API_ENDPOINT_URL }}
```

Reference: [gassorg/wiz-sarif-action-ingest](https://github.com/gassorg/wiz-sarif-action-ingest)

**Findings appear in:** Wiz → Vulnerabilities / Code (UVM), linked to the repo asset.

### Planned in Argus (native)

| Item | Status |
|------|--------|
| `argus format wiz` — Argus JSON → Wiz ingestion schema | Planned |
| `argus scan all --upload-wiz` — scan + GraphQL upload | Planned |
| MCP `upload_to_wiz` tool | Planned |

Until then, SARIF + `wiz-sarif-action-ingest` is the supported path.

---

## Pattern 3 — Argus orchestrates Wiz CLI (future `scan_wiz`)

Treat **Wiz CLI** like Semgrep/Trivy: an optional external runner inside Argus.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  CI / MCP   │────▶│    Argus     │────▶│  wizcli     │
│  argus scan │     │  tools/wiz.py│     │ dir/iac/    │
└─────────────┘     └──────┬───────┘     │ docker scan │
                           │            └──────┬──────┘
                           ▼                   │
                    Unified Finding            ▼
                    + SARIF export        Wiz Cloud (native)
```

**Implementation sketch** (`packages/python/src/argus/tools/wiz.py`):

```python
async def run_wiz_dir_scan(target: str, name: str, timeout: int = 600) -> ScanResult:
    if not is_tool_available("wizcli"):
        ...
    code, stdout, stderr = await run_command(
        ["wizcli", "dir", "scan", "--path", target, "--output", "json", "--name", name],
        timeout=timeout,
    )
    # Parse Wiz JSON → list[Finding], scan_type=ScanType.SAST or IAC
    return result
```

**CLI:** `argus scan wiz .`  
**MCP:** `scan_wiz` with `scan_type: dir | iac | docker`  
**Requires:** `wizcli` on PATH + `wizcli auth` (or env-based credentials in CI).

---

## Pattern 4 — Harness STO (enterprise CI)

If you use **Harness Security Testing Orchestration**, Wiz is a first-class scanner:

- **Orchestrated mode:** Harness runs `wizcli` repo / IaC / image scans.
- **Ingestion mode:** Point Harness at a SARIF/JSON file (e.g. Argus SARIF output).

Set target type to **Code Repository** in pipeline YAML. See [Harness Wiz repo scans](https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/wiz/repo-scans-with-wiz).

Argus fits as the **generator** step; Harness STO **normalizes and deduplicates** before Wiz/policy gates.

---

## Mapping Argus scan types → Wiz

| Argus command | Wiz equivalent | Notes |
|---------------|----------------|-------|
| `argus scan code` / `sast` | `wizcli dir scan` | Overlap on SAST; Argus adds Semgrep/Bandit/etc. |
| `argus scan secrets` | Wiz secrets in dir scan | Argus adds Gitleaks/TruffleHog |
| `argus scan iac` / `terraform` | `wizcli iac scan` | Both cover Checkov/tfsec-style checks |
| `argus scan sca` | Wiz SCA (in dir/image) | Argus: Trivy, pip-audit, npm audit |
| `argus scan container` | `wizcli docker scan` | Same class of findings |
| `argus scan ml` | *(no Wiz native)* | **Argus-only today** — good candidate for Wiz ingestion |
| `argus scan all` | Multiple Wiz CLI invocations | Run both or ingest Argus SARIF into Wiz |

---

## MCP / IDE workflow

Developers using Argus MCP in Cursor, VS Code, or Claude Desktop:

1. **Local:** `scan_all` / `scan_ml` → review in chat.
2. **CI:** Same repo runs Argus + Wiz CLI; Wiz enforces org policy, Argus feeds GitHub SARIF.
3. **Optional:** Nightly job ingests Argus SARIF into Wiz for security-team dashboards.

No Wiz credentials needed for local Argus MCP scans.

---

## Implementation checklist for your org

- [ ] Create Wiz service account with `create:external_data_ingestion`
- [ ] Add Wiz secrets to GitHub/org CI
- [ ] Add parallel workflow (Pattern 1) or SARIF ingest (Pattern 2)
- [ ] Define severity policy: fail build on Wiz policy **or** Argus `--fail-on high`
- [ ] (Optional) Open Argus issue/PR for native `tools/wiz.py` + `argus format wiz`

---

## Related

- [Argus SARIF workflow](../../.github/workflows/argus-sarif.yml) (on `main`)
- [Features roadmap — Wiz integration](../features-roadmap.md)
- [Wiz CLI](https://www.wiz.io/lp/wiz-cli)
- [Wiz + Harness](https://www.wiz.io/integrations/harness)
