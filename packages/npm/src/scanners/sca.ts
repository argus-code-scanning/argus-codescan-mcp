import { execa } from "execa";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { downgrade } from "./noise.js";
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
  /** Lockfile paths of the affected installs, e.g. node_modules/glob/node_modules/minimatch. */
  nodes?: string[];
  /** Vulnerable packages that depend on this one. */
  effects?: string[];
  isDirect?: boolean;
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
}

interface NpmAuditJson {
  auditReportVersion?: number;
  metadata?: { vulnerabilities?: { total?: number } };
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
/**
 * Installed versions from package-lock.json / npm-shrinkwrap.json, keyed both by package name
 * and by lockfile path (node_modules/a/node_modules/b), so npm audit's `nodes` can be resolved.
 */
export function installedVersions(lockfileText: string): Map<string, string[]> {
  const versions = new Map<string, Set<string>>();
  const add = (name: string, version: unknown) => {
    if (typeof version !== "string" || version.startsWith("file:")) return;
    if (!versions.has(name)) versions.set(name, new Set());
    versions.get(name)?.add(version);
  };
  let data: { packages?: Record<string, { version?: unknown; name?: unknown }>; dependencies?: unknown };
  try {
    data = JSON.parse(lockfileText);
  } catch {
    return new Map();
  }
  for (const [key, entry] of Object.entries(data.packages ?? {})) {
    const at = key.lastIndexOf("node_modules/");
    if (at < 0 || !entry) continue;
    add(typeof entry.name === "string" ? entry.name : key.slice(at + "node_modules/".length), entry.version);
    add(key, entry.version);
  }
  const walk = (deps: unknown) => {
    if (!deps || typeof deps !== "object") return;
    for (const [name, entry] of Object.entries(deps as Record<string, { version?: unknown; dependencies?: unknown }>)) {
      add(name, entry?.version);
      walk(entry?.dependencies);
    }
  };
  if (!data.packages) walk(data.dependencies);
  return new Map([...versions].map(([name, set]) => [name, [...set].sort()]));
}

/** Versions of the affected installs (npm audit `nodes`), or every installed version as a fallback. */
function affectedVersions(
  nodes: string[] | undefined,
  pkgName: string,
  installed?: Map<string, string[]>,
): string | undefined {
  if (!installed) return undefined;
  const fromNodes = [...new Set((nodes ?? []).flatMap((node) => installed.get(node) ?? []))].sort();
  const versions = fromNodes.length ? fromNodes : (installed.get(pkgName) ?? []);
  return versions.join(", ") || undefined;
}

/**
 * Every way `pkgName` is installed, from a direct dependency down, following npm audit's
 * `effects` (the vulnerable packages that depend on it). Paths through runtime dependencies
 * come first, then shorter ones: ["typeorm › tinyglobby › picomatch", "vitest › picomatch"].
 */
export function dependencyPaths(data: NpmAuditJson, pkgName: string, runtime: Set<string>): string[] {
  const vulns = data.vulnerabilities ?? {};
  const paths: string[][] = [];
  const queue: string[][] = [[pkgName]];
  const reached = new Set<string>();
  while (queue.length > 0 && paths.length < 50) {
    const chain = queue.shift() as string[];
    const head = chain[0];
    const entry = vulns[head];
    if (entry?.isDirect && !reached.has(head)) {
      reached.add(head);
      paths.push(chain);
    }
    for (const parent of entry?.effects ?? []) {
      if (!chain.includes(parent) && chain.length < 8) queue.push([parent, ...chain]);
    }
  }
  const rank = (chain: string[]) => (runtime.has(chain[0]) ? 0 : 1);
  return paths
    .sort((a, b) => rank(a) - rank(b) || a.length - b.length || a[0].localeCompare(b[0]))
    .map((chain) => chain.join(" \u203a "));
}

function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^[^\d]*/, "").split(/[.+-]/).slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
}

/**
 * What to do about an advisory, from npm audit's `fixAvailable`. npm sometimes "fixes" an
 * advisory by moving a direct dependency to an older major version; that is called out.
 */
export function fixGuidance(
  entry: NpmAuditEntry,
  pkgName: string,
  range: string,
  installed?: Map<string, string[]>,
): string {
  const fix = entry.fixAvailable;
  const affected = range ? ` (affected: ${range})` : "";
  if (fix === true) return "Run npm audit fix (no breaking changes).";
  if (!fix || typeof fix !== "object" || !fix.name || !fix.version) {
    return `No patched version of ${pkgName} is published yet${affected}. Update it when one is, or pin it with "overrides".`;
  }
  const current = (installed?.get(fix.name) ?? []).slice().sort(compareVersions).pop();
  if (current && compareVersions(fix.version, current) < 0) {
    return (
      `No safe fix yet: npm audit fix --force would downgrade ${fix.name} ${current} to ${fix.version}. ` +
      `Don't run it; wait for a patched ${pkgName}${affected} and pin it with "overrides".`
    );
  }
  return `Upgrade ${fix.name} to ${fix.version}${fix.isSemVerMajor ? " (major version: check for breaking changes)" : ""}.`;
}

/** npm audit counts every vulnerable package, including ones that only depend on another. */
export function auditCountNote(data: NpmAuditJson, findings: Finding[]): string | undefined {
  const total = data.metadata?.vulnerabilities?.total ?? Object.keys(data.vulnerabilities ?? {}).length;
  const packages = new Set(findings.map((f) => f.package)).size;
  if (!findings.length || total <= packages) return undefined;
  const advisories = new Set(findings.map((f) => `${f.package}\0${f.ruleId}`)).size;
  return (
    `${advisories} ${advisories === 1 ? "advisory" : "advisories"} in ${packages} ${packages === 1 ? "package" : "packages"}. ` +
    `npm audit reports ${total} vulnerable packages because it also counts every package that depends on one; ` +
    `those are listed under "via".`
  );
}

export function parseAuditFindings(
  data: NpmAuditJson,
  runtime: Set<string>,
  lockfile?: string,
  installed?: Map<string, string[]>,
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
      const severity = normalizeSeverity(via.severity ?? entry.severity);
      // Dev-only packages don't ship, so they are lowered one level like findings in tests.
      findings.push({
        title: !title
          ? `Vulnerable dependency: ${pkgName}`
          : title.toLowerCase().startsWith(pkgName.toLowerCase())
            ? title
            : `${pkgName}: ${title}`,
        severity: scope === "dev" ? downgrade(severity) : severity,
        ...(scope === "dev" ? { context: "dev-dependency" as const } : {}),
        tool: "npm-audit",
        file: lockfile,
        package: pkgName,
        version: affectedVersions(entry.nodes, pkgName, installed),
        description: `[${scope} dependency] ${pkgName} ${range}${title ? `: ${title}` : ""}`,
        url: via.url,
        ruleId: advisory,
        paths: dependencyPaths(data, pkgName, runtime),
        fix: fixGuidance(entry, pkgName, range, installed),
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
      let installed: Map<string, string[]> | undefined;
      try {
        installed = lockfile ? installedVersions(readFileSync(lockfile, "utf8")) : undefined;
      } catch {
        installed = undefined;
      }
      const findings = parseAuditFindings(data, runtime, lockfileRel, installed);
      result.findings.push(...findings);
      const note = auditCountNote(data, findings);
      if (note) (result.notes ??= []).push(projects.length > 1 ? `${lockfileRel}: ${note}` : note);
      result.projects?.push(project);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result.errors.push(`npm audit failed in ${project}: ${message}`);
    }
  }

  result.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return result;
}
