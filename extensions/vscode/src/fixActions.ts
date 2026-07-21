/**
 * User-initiated fix actions — never applied automatically during scans.
 */

import * as vscode from "vscode";
import type { Finding } from "./types.js";
import type { McpClient } from "./mcpClient.js";
import type { SecurityDiagnosticsProvider } from "./diagnostics.js";

const AUTOFIX_TOOLS = new Set(["eslint", "eslint-security", "semgrep"]);
const GUIDANCE_ONLY_TYPES = new Set(["secrets", "sca", "dast", "container"]);

function canAutofix(finding: Finding): boolean {
  if (GUIDANCE_ONLY_TYPES.has(finding.scan_type)) {
    return false;
  }
  const tool = finding.tool.toLowerCase().replace(/_/g, "-");
  return tool.startsWith("eslint") || AUTOFIX_TOOLS.has(tool);
}

export class ArgusFixCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  constructor(
    private readonly diagnosticsProvider: SecurityDiagnosticsProvider,
    private readonly getMcpClient: () => McpClient | undefined,
    private readonly getWorkspaceRoot: () => string | undefined
  ) {}

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (!diagnostic.source?.startsWith("argus-scan")) {
        continue;
      }

      const finding = this.diagnosticsProvider.getFinding(document.uri, diagnostic);
      if (!finding) {
        continue;
      }

      if (finding.fix_guidance) {
        const showFix = new vscode.CodeAction(
          "Argus: Show fix guidance",
          vscode.CodeActionKind.QuickFix
        );
        showFix.command = {
          command: "argus-scan.showFixGuidance",
          title: "Show fix guidance",
          arguments: [finding],
        };
        showFix.diagnostics = [diagnostic];
        actions.push(showFix);
      }

      if (canAutofix(finding)) {
        const applyFix = new vscode.CodeAction(
          "Argus: Apply automated fix",
          vscode.CodeActionKind.QuickFix
        );
        applyFix.command = {
          command: "argus-scan.applyFix",
          title: "Apply automated fix",
          arguments: [finding],
        };
        applyFix.diagnostics = [diagnostic];
        actions.push(applyFix);
      }
    }

    return actions;
  }
}

export async function showFixGuidance(finding: Finding): Promise<void> {
  const lines = [
    `# ${finding.title}`,
    "",
    `**Severity:** ${finding.severity} · **Tool:** ${finding.tool}`,
    finding.file ? `**File:** ${finding.file}:${finding.line}` : "",
    "",
    finding.description ? `## Description\n\n${finding.description}` : "",
    finding.fix_guidance ? `## Fix guidance\n\n${finding.fix_guidance}` : "",
    finding.cwe ? `\n**CWE:** ${finding.cwe}` : "",
    finding.cve ? `\n**CVE:** ${finding.cve}` : "",
  ].filter(Boolean);

  const doc = await vscode.workspace.openTextDocument({
    content: lines.join("\n"),
    language: "markdown",
  });
  await vscode.window.showTextDocument(doc, { preview: true });
}

export async function applyFix(
  finding: Finding,
  mcpClient: McpClient | undefined,
  workspaceRoot: string | undefined
): Promise<void> {
  if (!mcpClient || !workspaceRoot) {
    vscode.window.showErrorMessage("Argus scanner is not ready.");
    return;
  }

  if (GUIDANCE_ONLY_TYPES.has(finding.scan_type)) {
    vscode.window.showWarningMessage(
      `${finding.scan_type.toUpperCase()} findings cannot be auto-fixed. Use "Show fix guidance" instead.`
    );
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    `Apply automated fix for "${finding.title}" in ${finding.file}?`,
    { modal: true },
    "Apply fix"
  );
  if (confirm !== "Apply fix") {
    return;
  }

  const config = vscode.workspace.getConfiguration("argus-scan");

  try {
    const resultText = await mcpClient.applyFix({
      target: workspaceRoot,
      file: finding.file,
      tool: finding.tool,
      scan_type: finding.scan_type,
      rule_id: finding.rule_id,
      line: finding.line,
      fix_guidance: finding.fix_guidance,
      apply: true,
      semgrep_config: config.get<string>("semgrepConfig") ?? "auto",
    });

    const result = JSON.parse(resultText) as { applied?: boolean; message?: string };
    if (result.applied) {
      vscode.window.showInformationMessage(
        result.message || "Fix applied. Re-run scan to verify."
      );
    } else {
      vscode.window.showWarningMessage(
        result.message || "Automated fix could not be applied."
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Fix failed: ${message}`);
  }
}
