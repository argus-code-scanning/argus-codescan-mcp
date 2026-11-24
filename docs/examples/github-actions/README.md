# GitHub Actions examples

| File | What it does |
|---|---|
| [`argus-scheduled.yml`](argus-scheduled.yml) | Nightly full scan (02:00 UTC) plus a manual "Run workflow" button. Uploads SARIF to the Security tab, writes a job summary, and keeps **one** issue (label `argus-nightly`) for critical findings: opened when the first one appears, commented when new ones appear, closed when none are left. |

Copy the file to `.github/workflows/` in your repository. It uses the [Argus GitHub Action](../../../README.md#github-action).

**Manual runs** take three inputs: the branch to scan, `fail-on` (scheduled runs only report), and `notify` (`issue` or `none`).

**What counts as new:** a critical finding is identified by rule, file and message, not line number, so editing code above an existing finding doesn't report it again.

**Permissions:** `contents: read`, `security-events: write` (SARIF upload) and `issues: write` (the issue).
