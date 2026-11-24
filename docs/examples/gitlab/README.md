# GitLab CI

[`argus.gitlab-ci.yml`](argus.gitlab-ci.yml) adds an `argus-scan` job. Copy it into `.gitlab-ci.yml`, or include it:

```yaml
include:
  - remote: https://raw.githubusercontent.com/argus-code-scanning/argus-codescan-mcp/main/docs/examples/gitlab/argus.gitlab-ci.yml
```

| Pipeline | What happens |
|---|---|
| Merge request | Scans only the changed files (full scan when more than `ARGUS_PR_FILE_LIMIT` changed). Findings appear in the MR **Code Quality** widget (all GitLab tiers). With `ARGUS_GITLAB_TOKEN` set, one summary note is kept on the MR and edited on later pipelines. |
| Default branch | Full scan. |

The job fails when findings reach `ARGUS_FAIL_ON` (default `high`; `never` only reports). The SARIF report, summary and Code Quality JSON are kept as artifacts for 30 days.

| Variable | Default | |
|---|---|---|
| `ARGUS_SCAN_TYPE` | `all` | `all`, `sast`, `code`, `secrets`, `sca`, `iac`, `ml`, `malware`, `pci` |
| `ARGUS_FAIL_ON` | `high` | `critical`, `high`, `medium`, `low`, `never` |
| `ARGUS_VERSION` | latest | Pin `argus-scan`, for example `0.10.1` |
| `ARGUS_PR_FILE_LIMIT` | `50` | Changed-file count above which an MR gets a full scan |
| `ARGUS_GITLAB_TOKEN` | unset | Optional, masked. Project access token, `api` scope, Reporter role. Used only for the MR note. |

When you `include` the remote file, pin it to a commit (`.../argus-codescan-mcp/<sha>/docs/...`) rather than `main`.
