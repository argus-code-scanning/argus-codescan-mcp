/**
 * Bundled ESLint + security plugin — included in argus-codescan (all platforms).
 */

import { ESLint } from "eslint";
import pluginSecurity from "eslint-plugin-security";
import type { Finding, ScanResult } from "./types.js";

function mapSeverity(n: number): Finding["severity"] {
  if (n === 2) return "high";
  if (n === 1) return "moderate";
  return "low";
}

export async function runBundledEslint(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "eslint-security",
    scanType: "sast",
    target,
    findings: [],
    errors: [],
  };

  try {
    const recommended = pluginSecurity.configs.recommended;
    const configBlock = Array.isArray(recommended) ? recommended : [recommended];

    const eslint = new ESLint({
      cwd: target,
      overrideConfigFile: true,
      overrideConfig: [
        ...configBlock,
        {
          files: ["**/*.{js,mjs,cjs,jsx}"],
          rules: { "no-unused-vars": "warn" },
        },
      ],
      ignorePatterns: [
        "**/node_modules/**",
        "**/dist/**",
        "**/build/**",
        "**/.next/**",
        "**/coverage/**",
      ],
    });

    const results = await eslint.lintFiles(["**/*.{js,mjs,cjs,jsx}"]);

    if (results.length === 0) {
      return result;
    }

    for (const fileResult of results) {
      for (const msg of fileResult.messages) {
        const ruleId = msg.ruleId ?? "eslint";
        const isSecurity =
          ruleId.startsWith("security/") || ruleId === "no-unused-vars";
        if (!isSecurity) continue;

        result.findings.push({
          title: msg.message,
          severity: ruleId === "no-unused-vars" ? "low" : mapSeverity(msg.severity),
          tool: "eslint-security",
          file: fileResult.filePath,
          line: msg.line,
          ruleId,
        });
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!message.includes("No files matching")) {
      result.errors.push(message);
    }
  }

  return result;
}
