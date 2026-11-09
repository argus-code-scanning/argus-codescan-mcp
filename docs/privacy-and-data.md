# Privacy and data handling

How Argus handles your code and scan data when you run the CLI, MCP server, VS Code extension, or CI workflows.

## Local-first by default

| Mode | Data leaves your machine? |
|------|---------------------------|
| `argus scan …` (CLI) | **No** — scans run locally; no Argus phone-home |
| `argus mcp` / MCP tools | **No** — JSON-RPC over stdio to your IDE only |
| VS Code extension (local MCP) | **No** — same as MCP |
| External scanners (Semgrep, Trivy, …) | **Your machine only** — you install and run them |

Argus does not require an Argus account or cloud subscription for local scanning.

## When data can leave your environment

| Feature | What is sent | Opt-in |
|---------|--------------|--------|
| **Cloud dashboard upload** | Aggregated scan JSON | Yes — only if `ARGUS_API_KEY` is set or `--upload` is used |
| **GitHub SARIF workflow** | SARIF file to GitHub Code Scanning | Yes — you enable the workflow in your repo |
| **AI / MCP clients** | Tool results shown to the model | Yes — your IDE sends MCP responses to the AI provider you chose |

See [AGENT-UPLOAD.md](AGENT-UPLOAD.md) for cloud upload env vars and behavior.

## Scan artifacts on disk

- CLI `-o report.json` writes files where you specify.
- During a scan, Argus and the scanners it runs write temp files (for example the raw gitleaks report, which contains the secret values). Argus deletes its own; external scanners don't always clean up theirs, and by default both go to the shared system temp directory.

Two `argus scan …` / `argus review` flags control this:

| Flag | Effect |
|------|--------|
| `--no-persist` | Leave nothing on disk: the report goes to stdout only (`--output` is rejected), and all temp files from Argus **and** the scanners it launches go to a private `0700` directory that is deleted when the run ends, even if a scanner fails. |
| `--artifacts-dir DIR` | Put that private run directory under `DIR` (for example an encrypted volume) instead of the system temp directory. Can be used on its own to keep `-o` output while still cleaning up temp files. |

This works by pointing `TMPDIR`/`TMP`/`TEMP` at the run directory, which scanners inherit. Caches that tools keep in your home directory (for example Trivy's vulnerability database or Semgrep's rule cache) are not affected.

**CI best practices**

- Prefer ephemeral runners (GitHub-hosted, autoscaled containers): nothing survives the job.
- On self-hosted or shared runners, use `--no-persist`, or `--artifacts-dir "$RUNNER_TEMP"` when you need `-o` for a SARIF upload.
- Upload SARIF/JSON reports as short-lived artifacts (`retention-days`) rather than committing them.
- Keep `ARGUS_API_KEY` in CI secrets so it is masked in logs.

Retention policies in `.argus.yml` are planned ([#60](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/60), [#54](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/54)).

## Secrets and PII in reports

- Secret scanners may include **redacted** snippets in findings.
- Full code context can appear in JSON/Markdown/SARIF unless you enable redaction (planned [#53](https://github.com/argus-code-scanning/argus-codescan-mcp/issues/53)).
- Do not upload raw scan JSON to public tickets or shared AI chats if findings contain sensitive snippets.

## Environment variables affecting egress

| Variable | Effect |
|----------|--------|
| `ARGUS_API_KEY` | Enables post-scan upload to cloud dashboard when set |
| `ARGUS_API_URL` | Cloud API base URL (default localhost for dev) |
| `ARGUS_UPLOAD_SCRIPT` | Optional custom upload hook |
| `ARGUS_UPLOAD_REDACT` | `1` (default) redacts emails, SSNs and card numbers in uploads; `0` disables. Git remote credentials are always stripped. See [AGENT-UPLOAD.md](AGENT-UPLOAD.md#data-handling) |

Unset `ARGUS_API_KEY` to guarantee no cloud upload from MCP or CLI.

## Subprocessors and third parties

Local scans invoke **open-source CLI tools** you install (Semgrep, Trivy, Gitleaks, etc.). Those tools run on your hardware under their own licenses and network policies. Argus orchestrates them; it does not proxy your source code through Argus-operated servers during a normal local scan.

## GDPR / roles (high level)

- **Local use:** You are typically the **controller** of the code and findings; Argus software acts as a **tool** on your machine.
- **Cloud dashboard (if used):** Review the dashboard provider’s DPA for processor/controller roles and retention.

This document is informational, not legal advice.

## Related

- [SECURITY.md](../SECURITY.md) — reporting vulnerabilities
- [architecture.md](architecture.md) — MCP and data flow
- [features roadmap](features-roadmap.md) — planned data policy and PII features
