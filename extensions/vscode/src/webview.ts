/**
 * Webview panel for displaying security scan reports.
 */

import * as vscode from "vscode";
import type { AggregatedReport, Severity } from "./types.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
  unknown: "#9ca3af",
};

export class ScanDashboardPanel implements vscode.Disposable {
  private static instance: ScanDashboardPanel | undefined;
  private panel: vscode.WebviewPanel;
  private readonly extensionUri: vscode.Uri;

  private constructor(extensionUri: vscode.Uri) {
    this.extensionUri = extensionUri;
    this.panel = vscode.window.createWebviewPanel(
      "argus-scan.dashboard",
      "Security Scan Dashboard",
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    this.panel.onDidDispose(() => {
      ScanDashboardPanel.instance = undefined;
    });

    this.panel.webview.onDidReceiveMessage(this.handleMessage.bind(this));
    this.panel.webview.html = this.getLoadingHtml();
  }

  static createOrShow(extensionUri: vscode.Uri): ScanDashboardPanel {
    if (ScanDashboardPanel.instance) {
      ScanDashboardPanel.instance.panel.reveal(vscode.ViewColumn.Beside);
      return ScanDashboardPanel.instance;
    }
    ScanDashboardPanel.instance = new ScanDashboardPanel(extensionUri);
    return ScanDashboardPanel.instance;
  }

  showLoading(message: string = "Running security scan..."): void {
    this.panel.webview.html = this.getLoadingHtml(message);
  }

  showMarkdown(markdown: string, target: string): void {
    this.panel.webview.html = this.getMarkdownHtml(markdown, target);
  }

  showReport(report: AggregatedReport): void {
    this.panel.webview.html = this.getReportHtml(report);
  }

  showError(error: string): void {
    this.panel.webview.html = this.getErrorHtml(error);
  }

  private handleMessage(message: { command: string; data?: unknown }): void {
    if (message.command === "openFile") {
      const { file, line } = message.data as { file: string; line: number };
      vscode.workspace.openTextDocument(file).then((doc) => {
        vscode.window.showTextDocument(doc).then((editor) => {
          const pos = new vscode.Position(Math.max(0, line - 1), 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos));
        });
      });
    }
  }

  private getLoadingHtml(message = "Running security scan..."): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan</title>
  <style>
    body { 
      font-family: var(--vscode-font-family);
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      display: flex; align-items: center; justify-content: center; 
      height: 100vh; margin: 0; flex-direction: column; gap: 1rem;
    }
    .spinner {
      width: 48px; height: 48px;
      border: 4px solid var(--vscode-progressBar-background);
      border-top-color: var(--vscode-focusBorder);
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .message { font-size: 1.1em; opacity: 0.8; }
  </style>
</head>
<body>
  <div class="spinner"></div>
  <div class="message">${escapeHtml(message)}</div>
</body>
</html>`;
  }

  private getMarkdownHtml(markdown: string, target: string): string {
    // Simple markdown to HTML conversion for the report
    const html = markdownToHtml(markdown);
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report — ${escapeHtml(target)}</title>
  <style>
    body {
      font-family: var(--vscode-font-family);
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      padding: 1.5rem 2rem;
      max-width: 1000px;
      margin: 0 auto;
      line-height: 1.6;
    }
    h1 { color: var(--vscode-titleBar-activeForeground); border-bottom: 2px solid var(--vscode-focusBorder); padding-bottom: 0.5rem; }
    h2 { color: var(--vscode-titleBar-activeForeground); margin-top: 2rem; }
    h3 { color: var(--vscode-editor-foreground); margin-top: 1.5rem; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
    th, td { border: 1px solid var(--vscode-panel-border); padding: 0.5rem 0.75rem; text-align: left; }
    th { background: var(--vscode-list-hoverBackground); font-weight: 600; }
    tr:hover { background: var(--vscode-list-hoverBackground); cursor: pointer; }
    code, pre { 
      background: var(--vscode-textCodeBlock-background);
      border-radius: 4px;
      padding: 0.2em 0.4em;
      font-family: var(--vscode-editor-font-family);
      font-size: 0.9em;
    }
    pre { padding: 1rem; overflow-x: auto; }
    .badge-critical { background: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
    .badge-high { background: #ea580c; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
    .badge-medium { background: #d97706; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
    .badge-low { background: #2563eb; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
    details summary { cursor: pointer; user-select: none; }
    a { color: var(--vscode-textLink-foreground); }
  </style>
</head>
<body>${html}</body>
</html>`;
  }

  private getReportHtml(report: AggregatedReport): string {
    const summary = report.summary;
    const sevBadges = Object.entries(summary.by_severity)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `<span class="badge-${sev}">${count} ${sev}</span>`)
      .join(" ");

    const toolRows = report.results
      .map(
        (r) => `
        <tr>
          <td><code>${r.tool}</code></td>
          <td>${r.scan_type}</td>
          <td>${r.tool_available ? "✅" : "❌ Not installed"}</td>
          <td>${r.findings.length}</td>
          <td>${r.errors.length > 0 ? `⚠ ${r.errors[0].slice(0, 60)}` : "—"}</td>
        </tr>`
      )
      .join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Report</title>
  <style>
    body { font-family: var(--vscode-font-family); background: var(--vscode-editor-background); color: var(--vscode-editor-foreground); padding: 1.5rem 2rem; max-width: 1200px; margin: 0 auto; }
    h1, h2 { border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: .5rem; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
    th, td { border: 1px solid var(--vscode-panel-border); padding: .5rem .75rem; text-align: left; }
    th { background: var(--vscode-list-hoverBackground); }
    .badge-critical{background:#dc2626;color:#fff;padding:2px 8px;border-radius:12px;font-size:.8em}
    .badge-high{background:#ea580c;color:#fff;padding:2px 8px;border-radius:12px;font-size:.8em}
    .badge-medium{background:#d97706;color:#fff;padding:2px 8px;border-radius:12px;font-size:.8em}
    .badge-low{background:#2563eb;color:#fff;padding:2px 8px;border-radius:12px;font-size:.8em}
    code { background: var(--vscode-textCodeBlock-background); padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>🛡 Security Scan Report</h1>
  <p><strong>Target:</strong> <code>${escapeHtml(report.target)}</code></p>
  <p><strong>Total Findings:</strong> ${summary.total_findings} &nbsp; ${sevBadges}</p>

  <h2>Tool Results</h2>
  <table>
    <tr><th>Tool</th><th>Type</th><th>Status</th><th>Findings</th><th>Notes</th></tr>
    ${toolRows}
  </table>

  <h2>All Findings</h2>
  ${report.results.map((r) => renderResultSection(r)).join("\n")}
</body>
</html>`;
  }

  private getErrorHtml(error: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Error</title>
  <style>
    body { font-family: var(--vscode-font-family); background: var(--vscode-editor-background); color: var(--vscode-editor-foreground); padding: 2rem; }
    .error { background: var(--vscode-inputValidation-errorBackground); border: 1px solid var(--vscode-inputValidation-errorBorder); padding: 1rem; border-radius: 4px; }
    pre { white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <h1>❌ Scan Error</h1>
  <div class="error"><pre>${escapeHtml(error)}</pre></div>
  <p>Make sure <code>argus-scan</code> is installed: <code>pip install argus-scan</code></p>
</body>
</html>`;
  }

  dispose(): void {
    this.panel.dispose();
    ScanDashboardPanel.instance = undefined;
  }
}

function renderResultSection(result: { tool: string; findings: Array<{ severity: string; title: string; file: string; line: number; description: string }> }): string {
  if (!result.findings.length) return "";
  const rows = result.findings
    .slice(0, 100)
    .map(
      (f) => `<tr>
      <td><span class="badge-${f.severity}">${f.severity}</span></td>
      <td>${escapeHtml(f.title.slice(0, 60))}</td>
      <td><code>${escapeHtml(f.file ? f.file.split("/").pop() ?? "" : "")}</code>:${f.line}</td>
      <td>${escapeHtml(f.description.slice(0, 80))}</td>
    </tr>`
    )
    .join("");

  return `
  <h3>${escapeHtml(result.tool)} (${result.findings.length} findings)</h3>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Location</th><th>Description</th></tr>
    ${rows}
  </table>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function markdownToHtml(md: string): string {
  return md
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/^\| (.+) \|$/gm, (line) => {
      const cells = line.split("|").slice(1, -1);
      return `<tr>${cells.map((c) => `<td>${c.trim()}</td>`).join("")}</tr>`;
    })
    .replace(/(<tr>.*<\/tr>\n)+/g, (block) => `<table>${block}</table>`)
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    .replace(/(<li>.*<\/li>\n)+/g, (block) => `<ul>${block}</ul>`)
    .replace(/\n\n/g, "<br><br>");
}
