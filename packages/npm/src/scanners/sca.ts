import { execa } from "execa";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, ScanResult, Severity } from "./types.js";

interface NpmAuditVulnerability {
  name?: string;
  severity?: string;
  title?: string;
  url?: string;
  range?: string;
}

interface NpmAuditEntry {
  name?: string;
  severity?: string;
  via?: Array<string | NpmAuditVulnerability>;
  range?: string;
}

interface NpmAuditJson {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, NpmAuditEntry>;
  metadata?: {
    vulnerabilities?: Partial<Record<Severity | "total", number>>;
  };
}

function normalizeSeverity(value: string | undefined): Severity {
  const s = (value ?? "moderate").toLowerCase();
  if (s === "critical" || s === "high" || s === "moderate" || s === "low" || s === "info") {
    return s;
  }
  return "moderate";
}

function parseFindings(data: NpmAuditJson): Finding[] {
  const findings: Finding[] = [];
  const vulns = data.vulnerabilities ?? {};

  for (const [pkgName, entry] of Object.entries(vulns)) {
    const severity = normalizeSeverity(entry.severity);
    let title = `Vulnerable dependency: ${pkgName}`;
    let url: string | undefined;
    let description = entry.range ? `Affected range: ${entry.range}` : undefined;

    for (const via of entry.via ?? []) {
      if (typeof via === "object" && via !== null) {
        if (via.title) title = via.title;
        if (via.url) url = via.url;
        if (via.range) description = `Affected range: ${via.range}`;
        break;
      }
    }

    findings.push({
      title,
      severity,
      tool: "npm-audit",
      package: pkgName,
      description,
      url,
    });
  }

  const order: Record<Severity, number> = {
    critical: 0,
    high: 1,
    moderate: 2,
    low: 3,
    info: 4,
  };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return findings;
}

export async function runNpmAuditSca(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "npm-audit",
    scanType: "sca",
    target,
    findings: [],
    errors: [],
  };

  const packageJson = join(target, "package.json");
  if (!existsSync(packageJson)) {
    result.errors.push(`No package.json found at ${target}`);
    return result;
  }

  try {
    const { stdout } = await execa("npm", ["audit", "--json"], {
      cwd: target,
      reject: false,
      env: { ...process.env, FORCE_COLOR: "0" },
    });

    if (!stdout?.trim()) {
      result.errors.push("npm audit returned no output");
      return result;
    }

    let data: NpmAuditJson;
    try {
      data = JSON.parse(stdout) as NpmAuditJson;
    } catch {
      result.errors.push("Failed to parse npm audit JSON output");
      return result;
    }

    result.findings = parseFindings(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    result.errors.push(`npm audit failed: ${message}`);
  }

  return result;
}
