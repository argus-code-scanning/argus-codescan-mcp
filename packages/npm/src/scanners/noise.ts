/**
 * False-positive controls, matching argus-languages (Python):
 * - argus-ignore[rule-id]: reason   comments on the line or the comment line above
 * - findings in tests / docs / generated bundles are lowered one severity level
 * - rule confidence: low-confidence matches do not trigger --fail-on by default
 */

import { isAbsolute, relative, sep } from "node:path";
import type { Finding, FindingContext, ScanResult, Severity } from "./types.js";

const TEST_DIRS = new Set([
  "test", "tests", "__tests__", "__mocks__", "spec", "specs", "fixtures", "fixture",
  "testdata", "test-data", "test_data", "e2e", "cypress",
]);
const DOCS_DIRS = new Set(["docs", "doc", "examples", "example", "samples", "sample", "demo", "demos"]);

const TEST_FILE_RE =
  /(^test_.+\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|(Test|Tests|IT)\.(java|kt|cs)$|_spec\.rb$|Test\.php$)/;
const GENERATED_FILE_RE = /\.(min|bundle|chunk)\.[cm]?js$/;

/** "test", "docs", "generated" or undefined for a path relative to the scan root. */
export function pathContext(relativePath: string): FindingContext | undefined {
  const parts = relativePath.split(/[\\/]+/).filter(Boolean);
  const name = parts.pop() ?? "";
  const dirs = parts.map((p) => p.toLowerCase());
  if (dirs.some((d) => TEST_DIRS.has(d)) || TEST_FILE_RE.test(name)) return "test";
  if (GENERATED_FILE_RE.test(name)) return "generated";
  if (dirs.some((d) => DOCS_DIRS.has(d))) return "docs";
  return undefined;
}

const DOWNGRADE: Record<Severity, Severity> = {
  critical: "high",
  high: "moderate",
  moderate: "low",
  low: "info",
  info: "info",
};

export function downgrade(severity: Severity): Severity {
  return DOWNGRADE[severity] ?? severity;
}

export interface IgnoreMarker {
  /** undefined means every rule on the line */
  rules?: Set<string>;
  reason: string;
}

const IGNORE_RE = /argus-ignore(?:\[([^\]]*)\])?(.*)$/;
const COMMENT_CLOSERS = ["*/", "-->", "--}}", "%>", "#>"];

export function parseIgnore(line: string): IgnoreMarker | undefined {
  if (!line.includes("argus-ignore")) return undefined;
  const match = IGNORE_RE.exec(line);
  if (!match) return undefined;
  let rules: Set<string> | undefined;
  if (match[1] !== undefined) {
    const names = match[1].split(",").map((r) => r.trim()).filter(Boolean);
    rules = names.length ? new Set(names) : undefined;
  }
  const rest = match[2].trim();
  let reason = "";
  if (rest.startsWith(":")) {
    reason = rest.slice(1).trim();
    for (const closer of COMMENT_CLOSERS) {
      if (reason.endsWith(closer)) reason = reason.slice(0, -closer.length).trimEnd();
    }
  }
  return { rules, reason };
}

export function markerCovers(marker: IgnoreMarker, ruleId: string): boolean {
  return marker.rules === undefined || marker.rules.has(ruleId);
}

export const IGNORE_HINT = (ruleId: string): string =>
  ` (an argus-ignore comment here was not applied: add a reason, e.g. \`argus-ignore[${ruleId}]: why this is safe\`)`;

/**
 * Lower the severity of findings from external SAST tools (ESLint, Opengrep) that sit in
 * tests, docs or generated bundles. argus-native applies this itself while scanning.
 */
export function applyPathContext(result: ScanResult, root: string): ScanResult {
  for (const finding of result.findings) {
    if (!finding.file || finding.context) continue;
    const rel = isAbsolute(finding.file) ? relative(root, finding.file) : finding.file;
    if (rel.startsWith("..")) continue;
    const context = pathContext(rel.split(sep).join("/"));
    if (context) {
      finding.severity = downgrade(finding.severity);
      finding.context = context;
    }
  }
  return result;
}

/** Low-confidence rule matches are reported but only fail --fail-on when asked. */
export function countsTowardFailure(finding: Finding, includeLowConfidence = false): boolean {
  return includeLowConfidence || finding.confidence !== "low";
}
