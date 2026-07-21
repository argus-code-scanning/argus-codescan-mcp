# Argus Paid Features — Product & Implementation Plan

> **Use this document** as the source of truth for the Argus pricing page, roadmap, and paid-feature development.  
> Argus follows an **open-core** model: local scanning stays free and open source (MIT). Paid plans add cloud, team, and enterprise capabilities.

---

## Philosophy

| Principle | What it means |
|-----------|---------------|
| **Scanner stays free** | CLI, MCP server, local VS Code diagnostics, and open-source rule packs remain MIT-licensed forever. |
| **Pay for scale & convenience** | Teams pay for history, collaboration, compliance, CI integrations, and support — not for running a scan on their laptop. |
| **No AI lock-in** | Argus never requires a Cursor/Claude subscription. AI clients are optional. |
| **Transparent tiers** | Every paid feature maps to a concrete product capability, not artificial limits on core security checks. |

---

## Pricing Tiers (Website Copy)

### Free — Community

**For individuals and open-source projects.**

**Price:** $0 forever

**Includes:**

- Full CLI scanning (SAST, DAST, SCA, Secrets, IaC, Terraform, Ansible, Container)
- MCP server for Cursor, Claude Desktop, and other AI clients
- VS Code extension with inline diagnostics and local scan dashboard
- Markdown, JSON, and table report output
- Docker image (community edition)
- Built-in multi-language rules (`argus-languages`)
- npm package for Node/React projects (`argus-codescan`)
- `--fail-on` severity gating for basic CI

**Tagline for website:** *Run every scanner locally. No account. No subscription. No limits on scan execution.*

---

### Pro — Individual & Small Team

**For developers and small teams who want history, CI polish, and faster workflows.**

**Suggested price:** $19–29 / user / month *(adjust before launch)*

**Everything in Free, plus:**

| Feature | User benefit |
|---------|--------------|
| **Hosted scan dashboard** | View scan history, trends, and diffs over time — not just the latest stdout report |
| **SARIF export + GitHub Security upload** | Findings appear in GitHub’s Security tab and PR checks |
| **Baseline & suppression management** | Mark accepted risks, suppress false positives, set expiry dates |
| **Scheduled scans + alerts** | Email or Slack notifications when new critical/high findings appear |
| **Premium compliance rule packs** | PCI-DSS, HIPAA, SOC 2, CIS benchmark bundles |
| **VS Code Pro** | Unlimited scan-on-save, multi-root workspace scans, PDF/HTML export |
| **Priority support** | Email support with 48-hour SLA |

**Tagline for website:** *Keep scanning free. Pay for memory, CI integration, and peace of mind.*

---

### Team — Business

**For engineering orgs managing multiple repos and shared security policy.**

**Suggested price:** $49–79 / user / month *(adjust before launch)*

**Everything in Pro, plus:**

| Feature | User benefit |
|---------|--------------|
| **Organization workspace** | One dashboard across all connected repos |
| **Policy engine** | Enforce rules like “no critical findings on `main`” or “SCA required on every PR” |
| **RBAC** | Admin, developer, and read-only roles |
| **Audit log** | Who ran scans, who suppressed findings, when policies changed |
| **Shared custom rules** | Team-managed Semgrep/Argus rules synced to all clients |
| **SBOM export & supply-chain view** | Unified software bill of materials across projects |
| **GitHub / GitLab PR annotations** | Inline comments on changed lines with finding details |
| **SSO (Google / GitHub OAuth)** | Team login without shared API keys |

**Tagline for website:** *One security view for your whole engineering org.*

---

### Enterprise

**For regulated industries, air-gapped environments, and custom deployments.**

**Suggested price:** Custom (annual contract)

**Everything in Team, plus:**

| Feature | User benefit |
|---------|--------------|
| **SSO (SAML / OIDC)** | Okta, Azure AD, Google Workspace |
| **Managed DAST** | Scheduled OWASP ZAP scans against staging/production URLs |
| **On-prem / air-gapped deployment** | Self-hosted cloud stack with license key |
| **Private Docker registry image** | Pinned scanner versions, SLA, and security patches |
| **Compliance audit reports** | PDF exports mapped to PCI, HIPAA, SOC 2, ISO 27001 |
| **Custom scanner integrations** | Private tool adapters and professional services |
| **Dedicated support & SLA** | Named contact, 4-hour critical response |
| **Usage-based API** | Programmatic `POST /scan` for platforms that don’t run local tools |

**Tagline for website:** *Enterprise security orchestration — on your terms, in your environment.*

---

## What Stays Free Forever

Do **not** paywall these — they are core to adoption and the MIT promise:

- `argus scan *` CLI commands (all scan types)
- `argus mcp` MCP server and all 11 MCP tools
- Local VS Code Problems panel diagnostics
- Open-source bundled rules in `argus-languages`
- Community Docker image on GHCR
- Basic report formats (markdown, JSON, table, CSV)

---

## What Needs to Be Built

Below is the implementation checklist. Status reflects the repo **as of today** — all paid infrastructure is **net-new work**.

### Legend

| Status | Meaning |
|--------|---------|
| ✅ Exists | Already in the repo |
| 🔨 To build | Required for paid launch |
| 🌐 Cloud only | Lives in hosted service, not local CLI |

---

### Phase 1 — Foundation (ship before or with Pro launch)

| # | Feature | Tier | Status | Where to implement |
|---|---------|------|--------|-------------------|
| 1 | SARIF export formatter | Pro (or Free — recommended free for adoption) | 🔨 To build | `packages/python/src/argus/formatters/sarif.py` |
| 2 | SARIF in CLI `--format sarif` | Pro / Free | 🔨 To build | `packages/python/src/argus/cli.py` |
| 3 | SARIF in MCP `format` param | Pro / Free | 🔨 To build | `packages/python/src/argus/server.py` |
| 4 | SARIF in npm CLI | Pro / Free | 🔨 To build | `packages/npm/src/scanners/report.ts` |
| 5 | GitHub Actions SARIF upload workflow | Pro | 🔨 To build | `.github/workflows/argus-sarif.yml` |
| 6 | Cloud API scaffold (FastAPI) | Pro+ | 🔨 To build | `packages/cloud/api/` |
| 7 | Scan ingest endpoint (`POST /v1/scans`) | Pro+ | 🔨 To build | `packages/cloud/api/routes/scans.py` |
| 8 | Postgres schema (runs, findings, users) | Pro+ | 🔨 To build | `packages/cloud/api/db/` |
| 9 | User auth (API keys) | Pro+ | 🔨 To build | `packages/cloud/api/routes/auth.py` |
| 10 | Web dashboard (scan history) | Pro+ | 🔨 To build | `packages/cloud/web/` |
| 11 | VS Code cloud upload hook | Pro+ | 🔨 To build | `extensions/vscode/src/cloudClient.ts` |
| 12 | CLI `--upload` flag | Pro+ | 🔨 To build | `packages/python/src/argus/cli.py` |

**Existing foundation to reuse:**

- ✅ `Finding`, `ScanResult`, `AggregatedReport` — `packages/python/src/argus/models.py`
- ✅ Local VS Code dashboard UI — `extensions/vscode/src/webview.ts`
- ✅ Report formatting patterns — `packages/python/src/argus/utils.py`, `packages/npm/src/scanners/report.ts`

---

### Phase 2 — Pro Features

| # | Feature | Tier | Status | Where to implement |
|---|---------|------|--------|-------------------|
| 13 | Scan history & trend charts | Pro | 🔨 To build | `packages/cloud/web/app/dashboard/` |
| 14 | Diff view (scan vs previous scan) | Pro | 🔨 To build | `packages/cloud/api/services/diff.py` |
| 15 | Baseline management | Pro | 🔨 To build | `packages/cloud/api/routes/baselines.py` |
| 16 | Finding suppressions (with expiry) | Pro | 🔨 To build | `packages/cloud/api/routes/suppressions.py` |
| 17 | Scheduled scans (cron) | Pro | 🔨 To build | `packages/cloud/worker/scheduler.py` |
| 18 | Email alerts | Pro | 🔨 To build | `packages/cloud/worker/notifications/email.py` |
| 19 | Slack alerts | Pro | 🔨 To build | `packages/cloud/worker/notifications/slack.py` |
| 20 | Premium compliance rule packs | Pro | 🔨 To build | `packages/languages/.../bundled_rules/premium/` |
| 21 | Rule pack license check | Pro | 🔨 To build | `packages/cloud/api/middleware/entitlements.py` |
| 22 | VS Code scan-on-save (unlimited) | Pro | 🔨 To build | Gate in `extensions/vscode/src/extension.ts` |
| 23 | VS Code PDF/HTML export | Pro | 🔨 To build | `extensions/vscode/src/export.ts` |
| 24 | Stripe billing & subscriptions | Pro | 🔨 To build | `packages/cloud/billing/stripe.py` |
| 25 | Pricing page | Pro | 🔨 To build | `website/app/pricing/` |

---

### Phase 3 — Team Features

| # | Feature | Tier | Status | Where to implement |
|---|---------|------|--------|-------------------|
| 26 | Organization model (multi-repo) | Team | 🔨 To build | `packages/cloud/api/db/models/org.py` |
| 27 | Policy engine | Team | 🔨 To build | `packages/cloud/api/routes/policies.py` |
| 28 | RBAC (admin / dev / viewer) | Team | 🔨 To build | `packages/cloud/api/middleware/rbac.py` |
| 29 | Audit log | Team | 🔨 To build | `packages/cloud/api/routes/audit.py` |
| 30 | Shared custom rules repo sync | Team | 🔨 To build | `packages/cloud/api/routes/rules.py` |
| 31 | SBOM generation & export | Team | 🔨 To build | `packages/cloud/api/services/sbom.py` |
| 32 | GitHub PR review comments | Team | 🔨 To build | `packages/cloud/integrations/github.py` |
| 33 | GitLab MR comments | Team | 🔨 To build | `packages/cloud/integrations/gitlab.py` |
| 34 | OAuth team login | Team | 🔨 To build | `packages/cloud/api/routes/oauth.py` |

---

### Phase 4 — Enterprise Features

| # | Feature | Tier | Status | Where to implement |
|---|---------|------|--------|-------------------|
| 35 | SAML / OIDC SSO | Enterprise | 🔨 To build | `packages/cloud/api/routes/sso.py` |
| 36 | Managed DAST runner | Enterprise | 🔨 To build | `packages/cloud/worker/dast/` |
| 37 | On-prem Helm chart | Enterprise | 🔨 To build | `packages/cloud/deploy/helm/` |
| 38 | License key validation (air-gapped) | Enterprise | 🔨 To build | `packages/cloud/api/licensing/` |
| 39 | Private Docker image pipeline | Enterprise | 🔨 To build | `.github/workflows/docker-enterprise.yml` |
| 40 | Compliance PDF report generator | Enterprise | 🔨 To build | `packages/cloud/api/services/compliance_reports.py` |
| 41 | Public scan API with rate limits | Enterprise | 🔨 To build | `packages/cloud/api/routes/public_api.py` |
| 42 | Custom scanner adapter SDK | Enterprise | 🔨 To build | `docs/custom-scanner-integration.md` |

---

## Repo Structure (Target)

```
Code-testing-mcp/
├── packages/
│   ├── python/              ← Free: CLI, MCP, models (MIT)
│   ├── npm/                 ← Free: Node CLI (MIT)
│   ├── languages/           ← Free rules + premium rule packs
│   ├── cloud/               ← NEW: Paid hosted service (proprietary)
│   │   ├── api/             ← FastAPI backend
│   │   ├── web/             ← Next.js dashboard
│   │   ├── worker/          ← Schedulers, alerts, DAST
│   │   ├── billing/         ← Stripe
│   │   └── deploy/          ← Docker Compose, Helm
│   └── ...
├── extensions/vscode/       ← Free core + Pro cloud sync hooks
├── website/                 ← Marketing + pricing page
└── docs/
    └── paid-features.md     ← This document
```

**License split:**

| Component | License |
|-----------|---------|
| `packages/python`, `packages/npm`, `packages/languages`, VS Code core | MIT |
| `packages/cloud`, premium rule packs | Proprietary (or source-available) |
| Enterprise on-prem | Commercial license + support contract |

---

## Suggested Website Page Structure

Use these sections on `website/app/pricing/` (or equivalent):

1. **Hero** — “Argus is free to scan. Upgrade when your team needs more.”
2. **Tier cards** — Free / Pro / Team / Enterprise (copy from above)
3. **Feature comparison table** — Rows for each capability, columns per tier
4. **FAQ**
   - *Do I need a subscription to run scans locally?* → No.
   - *Does Argus require an AI subscription?* → No.
   - *What scanners does Argus use?* → 20+ open-source tools (Semgrep, Trivy, etc.).
   - *Can I self-host the paid dashboard?* → Enterprise only.
   - *Is the core project open source?* → Yes, MIT license.
5. **Roadmap teaser** — Link to GitHub milestones or “Coming soon” badges on unreleased features
6. **CTA** — “Start free” → install docs; “Contact sales” → Enterprise form

---

## Feature Comparison Table (for website)

| Feature | Free | Pro | Team | Enterprise |
|---------|:----:|:---:|:----:|:----------:|
| Local CLI & MCP scans | ✅ | ✅ | ✅ | ✅ |
| VS Code diagnostics | ✅ | ✅ | ✅ | ✅ |
| Docker community image | ✅ | ✅ | ✅ | ✅ |
| Markdown / JSON / CSV reports | ✅ | ✅ | ✅ | ✅ |
| SARIF export | ✅* | ✅ | ✅ | ✅ |
| Hosted scan dashboard | — | ✅ | ✅ | ✅ |
| Scan history & trends | — | ✅ | ✅ | ✅ |
| Baselines & suppressions | — | ✅ | ✅ | ✅ |
| Scheduled scans & alerts | — | ✅ | ✅ | ✅ |
| Compliance rule packs | — | ✅ | ✅ | ✅ |
| Org-wide policies | — | — | ✅ | ✅ |
| RBAC & audit log | — | — | ✅ | ✅ |
| PR/MR annotations | — | — | ✅ | ✅ |
| SBOM export | — | — | ✅ | ✅ |
| SAML / OIDC SSO | — | — | — | ✅ |
| Managed DAST | — | — | — | ✅ |
| On-prem / air-gapped | — | — | — | ✅ |
| Dedicated SLA & support | — | Priority | Standard | Dedicated |

*\*Recommended: keep SARIF free to drive CI adoption; gate advanced GitHub PR integrations behind Team.*

---

## Launch Roadmap

| Milestone | Deliverables | Unlocks tier |
|-----------|--------------|--------------|
| **M0 — Now** | Free CLI, MCP, VS Code, docs | Free |
| **M1 — SARIF** | SARIF export + GitHub Security workflow | Pro prep |
| **M2 — Cloud MVP** | API, auth, scan upload, web dashboard, Stripe | Pro |
| **M3 — Team** | Orgs, policies, RBAC, PR comments | Team |
| **M4 — Enterprise** | SSO, on-prem, managed DAST, compliance PDFs | Enterprise |

**Minimum viable paid launch (M2):**

1. User signup + Stripe checkout  
2. API key generation  
3. Scan upload from CLI or VS Code  
4. Web dashboard with history  
5. One paid differentiator beyond history (baselines **or** Slack alerts)

---

## FAQ for Internal Planning

**Should SARIF be free or paid?**  
Recommend **free**. It increases adoption and GitHub visibility. Charge for PR annotations, policies, and org features instead.

**Should we open-source the cloud package??**  
Keep `packages/cloud` proprietary. Open-source the scanner; monetize the hosted service.

**What competes with us?**  
Semgrep (open-core), Snyk (freemium), SonarQube (community + commercial), Trivy/Trivy Cloud. Argus differentiates as a **multi-scanner orchestrator** with MCP/AI-native workflow.

**What’s the fastest path to revenue?**  
M1 (SARIF) → M2 (cloud dashboard + Stripe). Target small teams already using Argus in CI who want history and suppressions.

---

## Related Docs

- [Architecture](./architecture.md) — Current system design
- [API Reference](./api-reference.md) — MCP tool surface
- [Getting Started](./getting-started.md) — Install guide for Free tier

---

*Last updated: July 2026. Pricing figures are placeholders — finalize before publishing to the website.*
