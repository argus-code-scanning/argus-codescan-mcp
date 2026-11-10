# Privacy & Data Handling

> Plain-language answers to "what does Argus read, keep, send, and share?" — for
> developers evaluating Argus, legal/compliance reviewers, and teams wiring the
> MCP server into Cursor, VS Code, or Claude Desktop.
>
> This document describes the current behavior of the Python package
> (`packages/python`) and its CI workflows. Every statement below is grounded in
> code — file references included so you can verify.

## The one-line summary

**By default Argus is local-only: it reads files you point it at, writes scan
results to a private temp directory, and makes no network calls.** Data only
leaves your machine if you (a) explicitly opt into cloud upload by setting
`ARGUS_API_KEY`, (b) upload SARIF/artifacts from CI yourself, or (c) paste scan
output into an AI chat yourself.

---

## 1. Local scans (CLI)

| Question | Answer |
|---|---|
| What files does it read? | Only the paths you pass as the scan target (a file, directory, or git diff range). Dependency checks additionally read your lockfiles; secret scans read file contents of the target tree. |
| Does it phone home? | **No.** With no `ARGUS_API_KEY` in the environment, cloud upload is disabled (`cloud_upload.py`: `enabled=bool(api_key)`). |
| What does it execute? | The bundled analyzers you invoke (SAST, SCA, secrets, IaC, container, malware, PCI checks). Nothing is installed, and no telemetry hooks exist. |
| Where do results go? | Scan JSON is written to a **fresh `0700` temp directory** created with `tempfile.mkdtemp(prefix="argus-run-")` under your system `TMP`/`TEMP` (`artifacts.py`). Nothing is written outside that run directory unless you pass `--output`/`--sarif` flags yourself. |

## 2. MCP / AI clients (Cursor, VS Code, Claude Desktop)

When you run Argus as an MCP server, the AI client can call these tools:
`scan_sast`, `scan_dast`, `scan_sca`, `scan_secrets`, `scan_iac`,
`scan_container`, `scan_terraform`, `scan_ansible`, `scan_ml`, `scan_malware`,
`scan_pci`, `review_code`, `scan_all`, `check_tools`, `explain_finding`,
`get_scan_report` (`server.py`).

What the AI model sees:

- **Finding data you asked for**: rule id, severity, file path, line, title and
  message — the same JSON the CLI prints.
- **Secret values are masked before they ever reach the model**: finding text is
  passed through a secret-literal masker that replaces secret values with
  `[REDACTED]` (`models.py`).
- **Your source code**: only when *you* attach it or when a tool argument
  explicitly points at files. The MCP server never streams your whole repo.
- The MCP transport is local (stdio) unless you configured a remote MCP relay
  yourself — Argus does not add one.

## 3. Cloud upload (opt-in only)

Cloud upload is **off unless `ARGUS_API_KEY` is set**. When you enable it:

- **What is sent**: a JSON payload with scan metadata (scan type, duration,
  pass/fail status vs your `ARGUS_FAIL_ON` threshold), the target label, and
  your findings (`build_upload_payload`, `cloud_upload.py`).
- **Redaction before upload** (on by default, `ARGUS_UPLOAD_REDACT=1`):
  - Emails, US SSNs, and card numbers in finding titles/messages are replaced
    with `[REDACTED_EMAIL]` / `[REDACTED_SSN]` / `[REDACTED_CARD]` — card
    numbers are only redacted when they pass a Luhn checksum
    (`redact_pii`).
  - Credentials embedded in URLs (`https://user:token@host/…`) are stripped to
    host-only (`strip_url_credentials`).
  - Long messages are truncated (`MAX_UPLOAD_MESSAGE_CHARS`).
- **What is never sent**: file contents, whole source files, or your git
  remote credentials. Only finding metadata that survived redaction.
- **Endpoint control**: `ARGUS_API_URL` lets you point uploads at your own
  ingest server (self-hosting the receiver is a supported posture).
  `ARGUS_UPLOAD_SCRIPT` lets you route uploads through your own script
  (e.g. a logging/audit proxy).

## 4. SARIF / CI (what GitHub receives)

If you use the provided GitHub workflows or pass `--sarif`, the SARIF file you
upload contains findings only: rule ids, severity, message, file path, and line
region — the standard Code Scanning fields. It contains **no source-code
snippets beyond the matched region description, no secrets (masked earlier),
and no environment data**. GitHub only receives what your own workflow
explicitly uploads (`github/codeql-action/upload-sarif` or equivalent);
Argus does not push anywhere on its own.

## 5. Logs & temp files

| Artifact | Location | Lifetime |
|---|---|---|
| Scan JSON / run artifacts | `argus-run-*` directory under `$TMP`/`$TEMP` (mode `0700`) | Until your OS temp cleaner removes it; Argus does not delete it automatically (deliberate: you may want to inspect the report). Delete with your usual temp hygiene. |
| CLI stdout/stderr | Your terminal or CI log | Whatever your log retention is. |
| MCP server logs | stderr of the MCP process | Same as above. |

## 6. Secrets vs PII — how redaction works today

Two independent layers:

1. **Findings layer (always on)**: secret *values* matched inside finding text
   are replaced with `[REDACTED]` before findings are returned, logged, or
   handed to MCP clients (`models.py`). A secrets scan tells you *that* a
   secret exists and where — the value itself does not travel onward.
2. **Upload layer (on by default for cloud upload)**: PII patterns in
   titles/messages (email, SSN, Luhn-valid cards) plus URL-credential stripping
   (`cloud_upload.py`). Planned: expanding the PII pattern set and adding a
   documented escape hatch for regulated environments.

## Quick reference — every data flow

| Flow | Default | How to enable/disable | What crosses |
|---|---|---|---|
| CLI local scan | on (local) | just don't set `ARGUS_API_KEY` | nothing leaves disk |
| MCP tools → AI client | local stdio | run/stop the MCP server | masked findings JSON |
| Cloud upload | **off** | set/unset `ARGUS_API_KEY` | redacted findings + scan metadata |
| SARIF upload in CI | your workflow | add/remove the upload step | findings (SARIF fields only) |
| Temp scan JSON | on (local) | OS temp cleanup | stays on your disk |

## Configuration knobs (cheat sheet)

| Variable | Default | Effect |
|---|---|---|
| `ARGUS_API_KEY` | unset | Unset = cloud upload fully disabled. Set = opt-in to upload. |
| `ARGUS_API_URL` | Argus default ingest | Point uploads at your own server. |
| `ARGUS_UPLOAD_SCRIPT` | unset | Route uploads through your own script/proxy. |
| `ARGUS_UPLOAD_REDACT` | `1` | `0` disables upload-time PII redaction (not recommended). |
| `ARGUS_FAIL_ON` | package default | Pass/fail threshold — affects uploaded status only, not data volume. |

---

*Found a gap in this document or a privacy concern in the code? Please open an
issue — privacy reports follow the [security policy](../SECURITY.md).*
