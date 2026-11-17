import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ScanReport, ScanResult, Severity } from "./types.js";
import { countsTowardFailure } from "./noise.js";
import { applyPolicy, loadPolicy } from "./policy.js";

function countBySeverity(results: ScanResult[]) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0, info: 0, total: 0 };
  for (const r of results) {
    for (const f of r.findings) {
      counts[f.severity]++;
      counts.total++;
    }
  }
  return counts;
}

export function buildReport(
  target: string,
  scanType: string,
  results: ScanResult[],
): ScanReport {
  const summary = countBySeverity(results);
  return { target, scanType, results, summary };
}

const LOCATION_WIDTH = 26;

/** Keep the end of long paths (file name and line), not the start. */
export function fitLocation(location: string, width = LOCATION_WIDTH): string {
  const text = location.length > width ? `\u2026${location.slice(-(width - 1))}` : location;
  return text.padEnd(width);
}

export function formatTable(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`Argus ${report.scanType.toUpperCase()} scan — ${report.target}`);
  lines.push(`Total findings: ${report.summary.total}`);
  lines.push(
    `  critical: ${report.summary.critical}  high: ${report.summary.high}  ` +
      `moderate: ${report.summary.moderate}  low: ${report.summary.low}`,
  );
  lines.push("");

  for (const result of report.results) {
    const notes = [...result.errors, ...(result.notes ?? [])];
    if (notes.length > 0) {
      lines.push(`[${result.tool}] notes:`);
      for (const err of notes) {
        for (const line of err.split("\n")) {
          lines.push(`  ${line}`);
        }
      }
      lines.push("");
    }
  }

  if (report.notes?.length) {
    lines.push("[policy] notes:");
    for (const note of report.notes) lines.push(`  ${note}`);
    lines.push("");
  }

  if (report.summary.total === 0) {
    lines.push("No security findings.");
    return lines.join("\n");
  }

  lines.push("SEVERITY  LOCATION                   FINDING");
  lines.push("-".repeat(78));

  for (const result of report.results) {
    for (const f of result.findings) {
      const sev = f.severity.toUpperCase().padEnd(8);
      const loc = fitLocation(
        f.package
          ? `${f.package}${f.version ? `@${f.version.split(", ").pop()}` : ""}`
          : f.file
            ? `${f.file}${f.line ? `:${f.line}` : ""}`
            : f.tool,
      );
      lines.push(`${sev} ${loc} ${f.title.slice(0, 42)}`);
      if (f.ruleId) {
        const tags = [
          f.confidence === "low" ? "low confidence" : "",
          f.context === "dev-dependency" ? "dev dependency" : f.context ? `in ${f.context}` : "",
        ].filter(Boolean);
        lines.push(`         [${f.tool}] ${f.ruleId}${tags.length ? ` (${tags.join(", ")})` : ""}`);
      }
      if (f.acceptedRisk) {
        const why = f.acceptedRisk.reason ? `: ${f.acceptedRisk.reason}` : "";
        lines.push(`         accepted risk until ${f.acceptedRisk.expires}${why} (does not fail the gate)`);
      } else if (f.acceptedRiskExpired) {
        lines.push(`         accepted risk EXPIRED on ${f.acceptedRiskExpired}: counts again`);
      }
      if (f.paths?.some((p) => p.includes(" \u203a "))) {
        const more = f.paths.length > 3 ? ` (+${f.paths.length - 3} more)` : "";
        lines.push(`         via ${f.paths.slice(0, 3).join(", ")}${more}`);
      }
      if (f.package && f.file && f.file.includes("/")) lines.push(`         lockfile: ${f.file}`);
      if (f.fix) lines.push(`         fix: ${f.fix}`);
      if (f.url) lines.push(`         ${f.url}`);
      if (f.description) lines.push(`         ${f.description}`);
    }
  }

  return lines.join("\n");
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "moderate", "low", "info"];

/** Findings at or above failOn; low-confidence ones only when includeLowConfidence. */
export function countFailing(
  report: ScanReport,
  failOn: Severity,
  includeLowConfidence = false,
): number {
  const threshold = SEVERITY_ORDER.indexOf(failOn);
  if (threshold < 0) return 0;
  let count = 0;
  for (const result of report.results) {
    for (const f of result.findings) {
      const rank = SEVERITY_ORDER.indexOf(f.severity);
      if (rank >= 0 && rank <= threshold && countsTowardFailure(f, includeLowConfidence)) count++;
    }
  }
  return count;
}

export function shouldFail(
  report: ScanReport,
  failOn: Severity,
  includeLowConfidence = false,
): boolean {
  return countFailing(report, failOn, includeLowConfidence) > 0;
}

function csvCell(value: string | number | undefined): string {
  const text = value === undefined ? "" : String(value);
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

export function formatCsv(report: ScanReport): string {
  const headers = [
    "severity",
    "scan_type",
    "tool",
    "file",
    "line",
    "rule_id",
    "title",
    "description",
    "package",
    "version",
    "url",
    "confidence",
    "context",
    "via",
    "fix",
  ];
  const rows = [headers.join(",")];

  for (const result of report.results) {
    for (const f of result.findings) {
      rows.push(
        [
          csvCell(f.severity),
          csvCell(result.scanType),
          csvCell(f.tool),
          csvCell(f.file),
          csvCell(f.line),
          csvCell(f.ruleId),
          csvCell(f.title),
          csvCell(f.description),
          csvCell(f.package),
          csvCell(f.version),
          csvCell(f.url),
          csvCell(f.confidence),
          csvCell(f.context),
          csvCell(f.paths?.join("; ")),
          csvCell(f.fix),
        ].join(","),
      );
    }
  }

  return rows.join("\n") + "\n";
}

export function defaultCsvPath(report: ScanReport): string {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  return join(process.cwd(), `argus-${report.scanType}-${stamp}.csv`);
}

export function writeScanCsv(report: ScanReport, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, formatCsv(report), "utf8");
}

export function printScanReport(
  report: ScanReport,
  format: "json" | "table" | "csv",
  failOn: Severity | "never",
  options: { csvPath?: string; writeCsv?: boolean; includeLowConfidence?: boolean; policyPath?: string } = {},
): number {
  applyPolicy(report, loadPolicy(report.target, options.policyPath));
  report.summary = countBySeverity(report.results); // suppressions may have removed findings
  for (const note of report.notes ?? []) console.error(`Policy: ${note}`);
  const writeCsv = options.writeCsv !== false;
  const csvPath = options.csvPath ?? defaultCsvPath(report);

  if (writeCsv) {
    writeScanCsv(report, csvPath);
    console.error(`CSV report written: ${csvPath}`);
  }

  if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else if (format === "csv") {
    console.log(formatCsv(report));
  } else {
    console.log(formatTable(report));
  }

  const includeLow = options.includeLowConfidence === true;
  if (failOn !== "never" && !includeLow) {
    const skipped = countFailing(report, failOn, true) - countFailing(report, failOn);
    if (skipped > 0) {
      console.error(
        `Note: ${skipped} low-confidence finding(s) at or above '${failOn}' are shown but do ` +
          "not fail the run. Add --fail-on-low-confidence to count them.",
      );
    }
  }
  if (failOn !== "never" && shouldFail(report, failOn, includeLow)) {
    console.error(`Failed: findings at or above '${failOn}' severity`);
    return 1;
  }

  return 0;
}
