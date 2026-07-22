/**
 * VS Code extension entry point for argus-scan.
 *
 * Registers commands, activates the MCP client, and wires up
 * diagnostics + the webview dashboard.
 */

import * as vscode from "vscode";
import { McpClient } from "./mcpClient.js";
import { SecurityDiagnosticsProvider } from "./diagnostics.js";
import { ScanDashboardPanel } from "./webview.js";
import {
  ArgusFixCodeActionProvider,
  applyFix,
  showFixGuidance,
} from "./fixActions.js";
import type { AggregatedReport, Finding } from "./types.js";

let mcpClient: McpClient | undefined;
let diagnosticsProvider: SecurityDiagnosticsProvider | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const outputChannel = vscode.window.createOutputChannel("Argus Security Scanner");
  mcpClient = new McpClient(outputChannel);
  diagnosticsProvider = new SecurityDiagnosticsProvider();

  context.subscriptions.push(
    outputChannel,
    mcpClient,
    diagnosticsProvider
  );

  // Register all commands
  context.subscriptions.push(
    vscode.commands.registerCommand("argus-scan.scanSast", () =>
      runScan("sast")
    ),
    vscode.commands.registerCommand("argus-scan.scanSca", () =>
      runScan("sca")
    ),
    vscode.commands.registerCommand("argus-scan.scanSecrets", () =>
      runScan("secrets")
    ),
    vscode.commands.registerCommand("argus-scan.scanIac", () =>
      runScan("iac")
    ),
    vscode.commands.registerCommand("argus-scan.scanDast", () =>
      runDastScan()
    ),
    vscode.commands.registerCommand("argus-scan.scanContainer", () =>
      runContainerScan()
    ),
    vscode.commands.registerCommand("argus-scan.scanAll", () =>
      runScan("all")
    ),
    vscode.commands.registerCommand("argus-scan.checkTools", () =>
      runCheckTools()
    ),
    vscode.commands.registerCommand("argus-scan.openDashboard", () => {
      ScanDashboardPanel.createOrShow(context.extensionUri);
    }),
    vscode.commands.registerCommand("argus-scan.clearDiagnostics", () => {
      diagnosticsProvider?.clear();
      vscode.window.showInformationMessage("Security diagnostics cleared.");
    }),
    vscode.commands.registerCommand("argus-scan.showFixGuidance", (finding: Finding) =>
      showFixGuidance(finding)
    ),
    vscode.commands.registerCommand("argus-scan.applyFix", (finding: Finding) =>
      applyFix(
        finding,
        mcpClient,
        vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
      )
    )
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new ArgusFixCodeActionProvider(
        diagnosticsProvider,
        () => mcpClient,
        () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
      ),
      { providedCodeActionKinds: ArgusFixCodeActionProvider.providedCodeActionKinds }
    )
  );

  // Scan on save (if configured)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("argus-scan");
      if (config.get<boolean>("scanOnSave")) {
        const workspaceRoot = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath;
        if (workspaceRoot) {
          runSilentSast(doc.uri.fsPath, workspaceRoot);
        }
      }
    })
  );

  outputChannel.appendLine("Argus Security Scanner extension activated");
}

export function deactivate(): void {
  mcpClient?.stop();
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

async function getTarget(): Promise<string | undefined> {
  // Use selected file/folder from explorer, or prompt
  const activeFile = vscode.window.activeTextEditor?.document.uri.fsPath;
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  const choice = await vscode.window.showQuickPick(
    [
      ...(workspaceRoot ? [{ label: "$(folder) Workspace root", value: workspaceRoot }] : []),
      ...(activeFile ? [{ label: "$(file) Current file", value: activeFile }] : []),
      { label: "$(search) Browse...", value: "__browse__" },
    ],
    { placeHolder: "Select scan target" }
  );

  if (!choice) return undefined;
  if (choice.value === "__browse__") {
    const uris = await vscode.window.showOpenDialog({
      canSelectFiles: true,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: "Select scan target",
    });
    return uris?.[0]?.fsPath;
  }
  return choice.value;
}

async function runScan(type: "sast" | "sca" | "secrets" | "iac" | "all"): Promise<void> {
  const target = await getTarget();
  if (!target || !mcpClient) return;

  const panel = ScanDashboardPanel.createOrShow(
    vscode.Uri.file(target) // extensionUri not available here — use target
  );

  panel.showLoading(`Running ${type.toUpperCase()} scan on ${target}...`);

  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? target;

  try {
    let result: string;
    switch (type) {
      case "sast":
        result = await mcpClient.scanSast(target);
        break;
      case "sca":
        result = await mcpClient.scanSca(target);
        break;
      case "secrets":
        result = await mcpClient.scanSecrets(target);
        break;
      case "iac":
        result = await mcpClient.scanIac(target);
        break;
      case "all":
        result = await mcpClient.scanAll(target);
        break;
    }

    panel.showMarkdown(result, target);

    const report = parseScanReport(result);
    if (report) {
      diagnosticsProvider?.applyReport(report, workspaceRoot);
      const total = report.summary?.total_findings ?? 0;
      vscode.window.showInformationMessage(
        `Security scan complete: ${total} finding(s) found.`
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    panel.showError(message);
    vscode.window.showErrorMessage(`Scan failed: ${message}`);
  }
}

async function runDastScan(): Promise<void> {
  const targetUrl = await vscode.window.showInputBox({
    placeHolder: "http://localhost:3000",
    prompt: "Enter the URL of the running web application to scan",
    validateInput: (value) =>
      value.startsWith("http://") || value.startsWith("https://")
        ? null
        : "Must start with http:// or https://",
  });

  if (!targetUrl || !mcpClient) return;

  const panel = ScanDashboardPanel.createOrShow(vscode.Uri.parse(targetUrl));
  panel.showLoading(`Running DAST scan on ${targetUrl}...`);

  try {
    const result = await mcpClient.scanDast(targetUrl);
    panel.showMarkdown(result, targetUrl);
  } catch (err) {
    panel.showError(err instanceof Error ? err.message : String(err));
  }
}

async function runContainerScan(): Promise<void> {
  const image = await vscode.window.showInputBox({
    placeHolder: "nginx:latest",
    prompt: "Enter container image name to scan",
  });

  if (!image || !mcpClient) return;

  const panel = ScanDashboardPanel.createOrShow(vscode.Uri.parse(`docker://${image}`));
  panel.showLoading(`Scanning container image ${image}...`);

  try {
    const result = await mcpClient.scanContainer(image);
    panel.showMarkdown(result, image);
  } catch (err) {
    panel.showError(err instanceof Error ? err.message : String(err));
  }
}

async function runCheckTools(): Promise<void> {
  if (!mcpClient) return;

  const panel = ScanDashboardPanel.createOrShow(vscode.Uri.parse("argus://tools"));
  panel.showLoading("Checking installed security tools...");

  try {
    const result = await mcpClient.checkTools();
    panel.showMarkdown(result, "Tool Availability");
  } catch (err) {
    panel.showError(err instanceof Error ? err.message : String(err));
  }
}

async function runSilentSast(file: string, workspaceRoot: string): Promise<void> {
  if (!mcpClient || !diagnosticsProvider) return;

  try {
    const result = await mcpClient.scanSast(file, { format: "json" });
    const report = parseScanReport(result);
    if (report) {
      diagnosticsProvider.applyReport(report, workspaceRoot);
    }
  } catch {
    // Silent scan — don't show errors
  }
}

function parseScanReport(result: string): AggregatedReport | undefined {
  try {
    return JSON.parse(result) as AggregatedReport;
  } catch {
    const jsonMatch = result.match(/```json\n([\s\S]+?)\n```/);
    if (!jsonMatch) {
      return undefined;
    }
    try {
      return JSON.parse(jsonMatch[1]) as AggregatedReport;
    } catch {
      return undefined;
    }
  }
}
