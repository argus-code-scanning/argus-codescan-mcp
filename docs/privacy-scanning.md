# Privacy scanning (GDPR / CCPA)

```bash
argus scan privacy .            # MCP: scan_privacy
argus scan pii .                # hardcoded personal data (emails, SSNs, names…) — MCP: scan_pii
```

**Argus finds code patterns, not legal compliance.** Every finding means "someone should look at this". No findings is not a statement that the project complies with GDPR, UK GDPR or CCPA. Use these scans to catch problems early in development and CI; use a privacy review (your DPO, legal team or privacy counsel) for compliance.

## What `scan privacy` checks

| Rule | Severity | Finds | CWE |
|---|---|---|---|
| `privacy-missing-consent-check` | medium | Analytics or ad trackers in the project and **no consent mechanism anywhere** (consent manager, Google Consent Mode, opt-in/out calls) | CWE-359 |
| `privacy-third-party-tracker` | low (info when consent exists) | Google Analytics / Tag Manager, Meta Pixel, Hotjar, Segment, Mixpanel, TikTok, LinkedIn, PostHog, Amplitude, Clarity | CWE-359 |
| `privacy-fingerprinting` | medium | FingerprintJS, ClientJS, evercookie | CWE-359 |
| `privacy-no-data-deletion-endpoint` | low | User/account endpoints but no account deletion, anonymisation or data export anywhere (GDPR Art. 15, 17, 20; CCPA right to delete) | CWE-359 |
| `privacy-retention-no-ttl` | low | Prisma models holding personal data with no `deletedAt` / `expiresAt` / retention field | CWE-359 |
| `privacy-non-eu-storage-region` | info | Storage or databases in non-EU regions (check transfer safeguards if they hold EU personal data) | CWE-359 |
| `pii-*` (from `pii.yaml`) | medium–high | Personal data written to logs, prints, error messages and monitoring tools (Sentry, Bugsnag, New Relic) | CWE-532 |

Consent, deletion and retention are project-level checks: they look across the whole repository for evidence. A consent banner or deletion process that lives outside the repository (tag manager, CMS, support process) is fine; ignore or [accept](../README.md) the finding with a note.

## When to use which

| Question | Use |
|---|---|
| Did someone commit real customer data or a real SSN? | `argus scan pii` |
| Do we log or send personal data where we shouldn't? | `argus scan privacy` (and `argus scan code`) |
| Do trackers wait for consent; can users delete and export their data; do we keep data forever? | `argus scan privacy` |
| Are we compliant? Do we need a DPIA, DPA or SCCs? | A privacy review, not a scanner |
