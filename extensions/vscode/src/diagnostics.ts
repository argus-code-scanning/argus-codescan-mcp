/**
 * VS Code diagnostics integration — converts scan findings into
 * Problems panel entries and inline decorations.
 */

import * as vscode from "vscode";
import type { AggregatedReport, Finding, Severity } from "./types.js";

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
  unknown: vscode.DiagnosticSeverity.Information,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

export class SecurityDiagnosticsProvider implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly decorationType: vscode.TextEditorDecorationType;
  /** Findings keyed by uri:line:code for user-initiated fix actions */
  private readonly findingsIndex = new Map<string, Finding>();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("argus-scan");

    this.decorationType = vscode.window.createTextEditorDecorationType({
      after: {
        margin: "0 0 0 2em",
        color: new vscode.ThemeColor("editorWarning.foreground"),
        fontStyle: "italic",
        fontSize: "11px",
      },
    });
  }

  applyReport(report: AggregatedReport, workspaceRoot: string): void {
    const diagnosticsMap = new Map<string, vscode.Diagnostic[]>();
    this.findingsIndex.clear();
    const config = vscode.workspace.getConfiguration("argus-scan");
    const minSeverity = config.get<Severity>("minSeverity") ?? "low";
    const minOrder = SEVERITY_ORDER[minSeverity];

    for (const result of report.results) {
      for (const finding of result.findings) {
        if (!finding.file) continue;
        if (SEVERITY_ORDER[finding.severity] > minOrder) continue;

        const uri = this.resolveUri(finding.file, workspaceRoot);
        if (!uri) continue;

        const diagnostic = this.findingToDiagnostic(finding);
        const key = uri.toString();
        this.findingsIndex.set(this.findingKey(key, diagnostic), finding);
        if (!diagnosticsMap.has(key)) {
          diagnosticsMap.set(key, []);
        }
        diagnosticsMap.get(key)!.push(diagnostic);
      }
    }

    // Apply to collection
    this.collection.clear();
    for (const [uriStr, diagnostics] of diagnosticsMap) {
      this.collection.set(vscode.Uri.parse(uriStr), diagnostics);
    }

    // Update decorations on active editor
    this.updateDecorations(diagnosticsMap, workspaceRoot);
  }

  private findingToDiagnostic(finding: Finding): vscode.Diagnostic {
    const line = Math.max(0, finding.line - 1);
    const col = Math.max(0, finding.column - 1);
    const range = new vscode.Range(line, col, line, col + 100);

    const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Information;

    const message = [
      finding.title,
      finding.description ? ` — ${finding.description}` : "",
    ]
      .join("")
      .slice(0, 200);

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = `argus-scan (${finding.tool})`;
    diagnostic.code = finding.rule_id || finding.cve || finding.cwe;

    if (finding.fix_guidance) {
      diagnostic.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(vscode.Uri.file(finding.file), new vscode.Position(line, col)),
          `Fix: ${finding.fix_guidance.slice(0, 120)}${finding.fix_guidance.length > 120 ? "…" : ""}`
        ),
      ];
    }

    return diagnostic;
  }

  getFinding(uri: vscode.Uri, diagnostic: vscode.Diagnostic): Finding | undefined {
    return this.findingsIndex.get(this.findingKey(uri.toString(), diagnostic));
  }

  private findingKey(uri: string, diagnostic: vscode.Diagnostic): string {
    const code =
      typeof diagnostic.code === "object"
        ? String(diagnostic.code.value)
        : String(diagnostic.code ?? "");
    return `${uri}:${diagnostic.range.start.line}:${code}`;
  }

  private resolveUri(file: string, workspaceRoot: string): vscode.Uri | null {
    if (!file) return null;

    const path = require("path") as typeof import("path");

    if (path.isAbsolute(file)) {
      return vscode.Uri.file(file);
    }
    return vscode.Uri.file(path.join(workspaceRoot, file));
  }

  private updateDecorations(
    diagnosticsMap: Map<string, vscode.Diagnostic[]>,
    workspaceRoot: string
  ): void {
    const config = vscode.workspace.getConfiguration("argus-scan");
    if (!config.get<boolean>("showInlineDecorations")) return;

    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) return;

    const key = activeEditor.document.uri.toString();
    const diagnostics = diagnosticsMap.get(key) ?? [];

    const decorations: vscode.DecorationOptions[] = diagnostics
      .slice(0, 20)
      .map((d) => ({
        range: d.range,
        renderOptions: {
          after: {
            contentText: `⚠ ${d.source}: ${d.message.slice(0, 60)}`,
          },
        },
      }));

    activeEditor.setDecorations(this.decorationType, decorations);
  }

  clear(): void {
    this.collection.clear();
    this.findingsIndex.clear();
    for (const editor of vscode.window.visibleTextEditors) {
      editor.setDecorations(this.decorationType, []);
    }
  }

  dispose(): void {
    this.collection.dispose();
    this.decorationType.dispose();
  }
}
