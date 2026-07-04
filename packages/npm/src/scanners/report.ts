import type { ScanReport, ScanResult, Severity } from "./types.js";

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
    if (result.errors.length > 0) {
      lines.push(`[${result.tool}] notes:`);
      for (const err of result.errors) {
        for (const line of err.split("\n")) {
          lines.push(`  ${line}`);
        }
      }
      lines.push("");
    }
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
      const loc = f.file
        ? `${f.file}${f.line ? `:${f.line}` : ""}`.slice(0, 26).padEnd(26)
        : (f.package ?? f.tool).slice(0, 26).padEnd(26);
      lines.push(`${sev} ${loc} ${f.title.slice(0, 42)}`);
      if (f.ruleId) lines.push(`         [${f.tool}] ${f.ruleId}`);
      if (f.url) lines.push(`         ${f.url}`);
      if (f.description) lines.push(`         ${f.description}`);
    }
  }

  return lines.join("\n");
}

export function shouldFail(report: ScanReport, failOn: Severity): boolean {
  const order: Severity[] = ["critical", "high", "moderate", "low", "info"];
  const threshold = order.indexOf(failOn);
  if (threshold < 0) return false;

  for (const sev of order.slice(0, threshold + 1)) {
    if (report.summary[sev] > 0) return true;
  }
  return false;
}

export function printScanReport(
  report: ScanReport,
  format: "json" | "table",
  failOn: Severity | "never",
): number {
  if (format === "json") {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatTable(report));
  }

  if (failOn !== "never" && shouldFail(report, failOn)) {
    console.error(`Failed: findings at or above '${failOn}' severity`);
    return 1;
  }

  return report.summary.total > 0 ? 1 : 0;
}
