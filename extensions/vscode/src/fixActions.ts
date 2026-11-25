/**
 * User-initiated fix actions — never applied automatically during scans.
 */

import * as vscode from "vscode";
import type { Finding } from "./types.js";
import type { McpClient } from "./mcpClient.js";
import type { SecurityDiagnosticsProvider } from "./diagnostics.js";
import { buildAiFixPrompt, excerptAround, shouldIncludeCode } from "./aiPrompt.js";

const AUTOFIX_TOOLS = new Set(["eslint", "eslint-security", "semgrep"]);
/** Rules argus apply_fix fixes whatever scanner reported them (GitHub Actions workflows). */
const AUTOFIX_RULES = ["github-actions-mutable-action-tag", "run-shell-injection"];
const GUIDANCE_ONLY_TYPES = new Set(["secrets", "sca", "dast", "container"]);

function canAutofix(finding: Finding): boolean {
  if (GUIDANCE_ONLY_TYPES.has(finding.scan_type)) {
    return false;
  }
  const rule = (finding.rule_id || "").toLowerCase();
  if (AUTOFIX_RULES.some((r) => rule.endsWith(r))) {
    return true;
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

      const askAi = new vscode.CodeAction(
        "Argus: Ask AI to fix (copy prompt)",
        vscode.CodeActionKind.QuickFix
      );
      askAi.command = {
        command: "argus-scan.askAiToFix",
        title: "Ask AI to fix",
        arguments: [finding, document.uri],
      };
      askAi.diagnostics = [diagnostic];
      actions.push(askAi);

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

/** Copy a ready-to-paste prompt (finding + nearby code) for the user's AI chat. */
export async function askAiToFix(finding: Finding, uri?: vscode.Uri): Promise<void> {
  let excerpt;
  if (shouldIncludeCode(finding)) {
    try {
      const target =
        uri ??
        (finding.file && vscode.workspace.workspaceFolders?.[0]
          ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, finding.file)
          : undefined);
      if (target) {
        const doc = await vscode.workspace.openTextDocument(target);
        excerpt = excerptAround(doc.getText(), finding.line, doc.languageId);
      }
    } catch {
      // File moved or unreadable: the prompt still has the finding details.
    }
  }

  await vscode.env.clipboard.writeText(buildAiFixPrompt(finding, excerpt));

  // Open the editor's AI chat when one is available (VS Code Chat / Copilot, Cursor).
  const commands = await vscode.commands.getCommands(true);
  const chat = ["workbench.action.chat.open", "aichat.newchataction"].find((c) => commands.includes(c));
  const note = shouldIncludeCode(finding)
    ? "Prompt copied. Paste it into your AI chat."
    : "Prompt copied (the secret itself is not included). Paste it into your AI chat.";
  const choice = await vscode.window.showInformationMessage(note, ...(chat ? ["Open chat"] : []));
  if (choice === "Open chat" && chat) {
    await vscode.commands.executeCommand(chat);
  }
}
