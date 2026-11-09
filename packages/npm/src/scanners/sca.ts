import { execa } from "execa";
import { existsSync, lstatSync, readdirSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import type { Finding, ScanResult, Severity } from "./types.js";

interface NpmAuditAdvisory {
  source?: number | string;
  name?: string;
  severity?: string;
  title?: string;
  url?: string;
  range?: string;
}

interface NpmAuditEntry {
  name?: string;
  severity?: string;
  via?: Array<string | NpmAuditAdvisory>;
  range?: string;
}

interface NpmAuditJson {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, NpmAuditEntry>;
  error?: { code?: string; summary?: string };
}

export const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"] as const;

/** Same list as SKIP_SCAN_DIRS in the Python package (argus/utils.py). */
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", "__pycache__",
  "target", "bin", "obj", ".venv", "venv", ".terraform", ".idea", ".vscode", "Pods",
  "DerivedData", ".dart_tool",
]);

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  moderate: 2,
  low: 3,
  info: 4,
};

function normalizeSeverity(value: string | undefined): Severity {
  const s = (value ?? "moderate").toLowerCase();
  if (s === "critical" || s === "high" || s === "moderate" || s === "low" || s === "info") {
    return s;
  }
  return "moderate";
}

/** Directories under `root` that contain a package.json, skipping node_modules and symlinks. */
export function findPackageDirs(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    if (entries.includes("package.json")) found.push(dir);
    for (const name of entries) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      try {
        const st = lstatSync(full);
        if (st.isDirectory() && !st.isSymbolicLink()) walk(full);
      } catch {
        // unreadable entry: skip
      }
    }
  };
  walk(root);
  return found.sort();
}

function lockfileIn(dir: string): string | undefined {
  return NPM_LOCKFILES.map((name) => join(dir, name)).find((path) => existsSync(path));
}

function isInside(dir: string, parent: string): boolean {
  const rel = relative(parent, dir);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function advisoryId(advisory: NpmAuditAdvisory): string {
  const url = advisory.url ?? "";
  if (url.includes("GHSA-")) return url.slice(url.lastIndexOf("/") + 1);
  return String(advisory.source ?? advisory.title ?? "unknown");
}

/**
 * One finding per (package, advisory). Entries in `via` that are plain strings point
 * at another vulnerable package, which carries the advisory itself, so they are skipped.
 * `runtime` holds the package names `npm audit --omit=dev` still reports.
 */
export function parseAuditFindings(
  data: NpmAuditJson,
  runtime: Set<string>,
  lockfile?: string,
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const [pkgName, entry] of Object.entries(data.vulnerabilities ?? {})) {
    for (const via of entry.via ?? []) {
      if (typeof via !== "object" || via === null) continue;
      const advisory = advisoryId(via);
      const key = `${pkgName}\0${advisory}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const scope = runtime.has(pkgName) ? "runtime" : "dev";
      const title = via.title ?? "";
      const range = via.range ?? entry.range ?? "";
      findings.push({
        title: !title
          ? `Vulnerable dependency: ${pkgName}`
          : title.toLowerCase().startsWith(pkgName.toLowerCase())
            ? title
            : `${pkgName}: ${title}`,
        severity: normalizeSeverity(via.severity ?? entry.severity),
        tool: "npm-audit",
        file: lockfile,
        package: pkgName,
        description: `[${scope} dependency] ${pkgName} ${range}${title ? `: ${title}` : ""}`,
        url: via.url,
        ruleId: advisory,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return findings;
}

async function npmAudit(cwd: string, omitDev: boolean): Promise<string> {
  const args = ["audit", "--json", ...(omitDev ? ["--omit=dev"] : [])];
  const { stdout } = await execa("npm", args, {
    cwd,
    reject: false,
    env: { ...process.env, FORCE_COLOR: "0" },
  });
  return stdout ?? "";
}

function parseJson(text: string): NpmAuditJson | undefined {
  try {
    const data: unknown = JSON.parse(text);
    return data && typeof data === "object" ? (data as NpmAuditJson) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Run npm audit in every npm project (package.json + lockfile) under `target`.
 *
 * Emits one finding per advisory and marks whether the vulnerable package is a
 * runtime or dev-only dependency. Mirrors `run_npm_audit` in the Python package.
 */
export async function runNpmAuditSca(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "npm-audit",
    scanType: "sca",
    target,
    findings: [],
    errors: [],
    projects: [],
  };

  let root = target;
  try {
    if (!lstatSync(target).isDirectory()) {
      const name = basename(target);
      root = name === "package.json" || (NPM_LOCKFILES as readonly string[]).includes(name)
        ? dirname(target)
        : "";
    }
  } catch {
    root = "";
  }

  const packageDirs = root ? findPackageDirs(root) : [];
  if (packageDirs.length === 0) {
    result.errors.push(`No package.json found at ${target}`);
    return result;
  }

  const projects = packageDirs.filter((dir) => lockfileIn(dir) !== undefined);
  // Workspace members share the root lockfile; only flag packages nothing covers.
  const unlocked = packageDirs.filter((dir) => !projects.some((p) => isInside(dir, p)));
  if (unlocked.length > 0) {
    result.errors.push(
      "npm audit needs a lockfile; skipped (run npm install to create one): " +
        unlocked.join(", "),
    );
  }

  for (const project of projects) {
    const lockfile = lockfileIn(project);
    try {
      const [full, prod] = await Promise.all([npmAudit(project, false), npmAudit(project, true)]);
      const data = parseJson(full);
      if (!data || data.error) {
        const detail = data?.error?.summary ?? (full.trim() ? "unreadable output" : "no output");
        result.errors.push(`npm audit failed in ${project}: ${detail}`);
        continue;
      }
      const runtime = new Set(Object.keys(parseJson(prod)?.vulnerabilities ?? {}));
      const lockfileRel = lockfile && relative(root, lockfile).split(sep).join("/");
      result.findings.push(...parseAuditFindings(data, runtime, lockfileRel));
      result.projects?.push(project);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result.errors.push(`npm audit failed in ${project}: ${message}`);
    }
  }

  result.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return result;
}
