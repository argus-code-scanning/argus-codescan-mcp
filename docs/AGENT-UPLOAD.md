# Agent cloud upload

Upload scan results to the Argus cloud dashboard after each scan. Local scanning still works without any API key.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARGUS_API_KEY` | Yes (to upload) | — | API key from the dashboard (`arg_live_…`) |
| `ARGUS_API_URL` | No | `http://localhost:4000/v1` | Cloud API base URL |
| `ARGUS_FAIL_ON` | No | `high` | Severity threshold for `status: failed` in uploads |
| `ARGUS_UPLOAD_SCRIPT` | No | — | Optional Node script path instead of direct HTTP |

## MCP config (Cursor / Claude)

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"],
      "env": {
        "ARGUS_API_URL": "http://localhost:4000/v1",
        "ARGUS_API_KEY": "arg_live_PASTE_YOUR_KEY"
      }
    }
  }
}
```

Restart your AI client after saving.

Print the same template from the CLI:

```bash
argus mcp --config
```

## When upload runs

- **MCP server:** after every `scan_*` and `scan_all` tool call, if `ARGUS_API_KEY` is set
- **CLI:** after every `argus scan …` when `ARGUS_API_KEY` is set, or when `--upload` is passed
- **Skip:** `--no-upload` on CLI, or unset `ARGUS_API_KEY`

Upload failures are logged but do not fail the scan.

## Local dev checklist

1. Start backend: `cd backend-nodejs && npm run start:dev`
2. Start dashboard: `cd cloud-dashboard && npm run dev`
3. Log in at http://localhost:3001/login (`dev@example.com` / `argus-admin`)
4. Create an API key under **API keys**
5. Set `ARGUS_API_URL` and `ARGUS_API_KEY` in MCP env (above)
6. Run a scan — refresh http://localhost:3001/dashboard

## CLI examples

```bash
export ARGUS_API_URL=http://localhost:4000/v1
export ARGUS_API_KEY=arg_live_xxxx

argus scan all /path/to/project
argus scan sast . --upload --fail-on high
argus scan secrets . --no-upload
```

## Upload payload

The agent sends JSON to `POST {ARGUS_API_URL}/scans`:

```json
{
  "status": "passed",
  "failOn": "high",
  "durationSec": 12,
  "scanType": "sast",
  "target": "/path/to/project",
  "repo": "git@github.com:org/repo.git",
  "branch": "main",
  "commit": "abc123…",
  "findings": [
    {
      "ruleId": "security/detect-eval-with-expression",
      "title": "eval with expression",
      "severity": "high",
      "file": "src/api.js",
      "line": 42,
      "scanner": "eslint-security",
      "message": "Avoid eval()"
    }
  ]
}
```

`repo`, `branch`, and `commit` are detected from git automatically.

## Optional Node upload script

If you use `ARGUS_UPLOAD_SCRIPT`, the agent writes the same JSON to a temp file and runs:

```bash
node "$ARGUS_UPLOAD_SCRIPT" /tmp/scan-xyz.json
```

Direct HTTP upload is used when the script is not set.
