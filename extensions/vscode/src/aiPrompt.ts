/**
 * "Ask AI to fix": the prompt copied to the clipboard for an AI chat.
 * No vscode imports, so it can be unit-tested with plain Node.
 */

import type { Finding } from "./types.js";

/** Lines of code shown above and below the finding. */
export const CONTEXT_LINES = 6;
const MAX_LINE_LENGTH = 300;

export interface CodeExcerpt {
  /** 1-based number of the first line in `lines`. */
  startLine: number;
  lines: string[];
  languageId?: string;
}

/** The lines around `line` (1-based) from a document's text. */
export function excerptAround(text: string, line: number, languageId?: string): CodeExcerpt {
  const all = text.split(/\r?\n/);
  const at = Math.min(Math.max(line, 1), Math.max(all.length, 1));
  const start = Math.max(1, at - CONTEXT_LINES);
  const end = Math.min(all.length, at + CONTEXT_LINES);
  return { startLine: start, lines: all.slice(start - 1, end), languageId };
}

/** Secrets must never be pasted into a chat, even as context. */
export function shouldIncludeCode(finding: Finding): boolean {
  return finding.scan_type !== "secrets";
}

function clip(line: string): string {
  return line.length > MAX_LINE_LENGTH ? `${line.slice(0, MAX_LINE_LENGTH)} …` : line;
}

export function buildAiFixPrompt(finding: Finding, excerpt?: CodeExcerpt): string {
  const location = finding.file ? `${finding.file}${finding.line > 0 ? `:${finding.line}` : ""}` : "";
  const meta = [
    `- Severity: ${finding.severity}`,
    `- Scanner: ${finding.tool}${finding.rule_id ? ` (rule ${finding.rule_id})` : ""}`,
    location ? `- Location: ${location}` : "",
    finding.cwe ? `- CWE: ${finding.cwe}` : "",
    finding.cve ? `- CVE: ${finding.cve}` : "",
  ].filter(Boolean);

  const parts = [
    `Fix this security issue reported by Argus: **${finding.title}**`,
    "",
    ...meta,
  ];
  if (finding.description) {
    parts.push("", "What the scanner says:", finding.description.trim());
  }
  if (finding.fix_guidance) {
    parts.push("", "Suggested fix:", finding.fix_guidance.trim());
  }

  if (!shouldIncludeCode(finding)) {
    parts.push(
      "",
      "The code is not included because this finding is a secret. Do not ask me to paste it.",
      "Tell me how to remove the secret from the code (read it from an environment variable or a",
      "secret manager), and remind me to rotate it, since it may already be in git history."
    );
  } else if (excerpt && excerpt.lines.length) {
    const width = String(excerpt.startLine + excerpt.lines.length - 1).length;
    const numbered = excerpt.lines.map((l, i) => {
      const n = excerpt.startLine + i;
      const mark = n === finding.line ? ">" : " ";
      return `${mark} ${String(n).padStart(width)} | ${clip(l)}`;
    });
    parts.push("", `Code (line ${finding.line} marked with >):`, "```" + (excerpt.languageId ?? ""), ...numbered, "```");
  }

  if (shouldIncludeCode(finding)) {
    parts.push(
      "",
      "Please:",
      "1. Fix only this issue and keep the code's behaviour otherwise unchanged.",
      "2. Don't silence the scanner (no ignore comments, no disabling the check).",
      "3. Show the changed code and explain in one or two sentences why it is safe now."
    );
  }
  return parts.join("\n");
}
