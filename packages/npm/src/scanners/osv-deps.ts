/**
 * Known vulnerabilities in dependencies from every lockfile, via OSV. Same behaviour and ids as
 * argus-scan (Python) argus/tools/osv_deps.py + dep_graph.py.
 *
 * Reads yarn.lock, pnpm-lock.yaml, requirements*.txt, poetry.lock, uv.lock, Pipfile.lock,
 * go.mod (and its Go toolchain), pubspec.lock (Dart / Flutter), Cargo.lock, Gemfile.lock,
 * packages.lock.json (.NET), composer.lock, pom.xml and gradle.lockfile. package-lock.json is
 * left to npm audit when npm is installed.
 *
 * One finding per package and lockfile: every advisory for that version, the version that fixes
 * all of them, how the package gets into the project ("via a › b"), dev-only packages lowered one
 * level. Only ecosystem / name / version go to api.osv.dev; ARGUS_NO_NETWORK=1 or --no-network
 * skips the check. No YAML / TOML dependency: the lockfile formats are read line by line.
 */

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";
import { downgrade } from "./noise.js";
import type { Finding, ScanResult, Severity } from "./types.js";

const TOOL = "osv-deps";
export const ARROW = " › ";
const OSV = "https://api.osv.dev/v1";
const BATCH = 1000;
const MAX_DETAILS = 400;
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".venv", "venv", ".tox", "__pycache__", "dist", "build", "vendor",
  ".next", "coverage", "target", ".gradle", ".mvn", ".terraform", ".dart_tool", "Pods",
]);

export interface Pkg {
  ecosystem: string;
  name: string;
  version: string;
  line: number;
}

export class DependencyGraph {
  direct = new Set<string>();
  dev = new Set<string>();
  devDirect = new Set<string>();
  edges = new Map<string, Set<string>>();

  addEdge(parent: string, child: string): void {
    if (parent === child) return;
    if (!this.edges.has(parent)) this.edges.set(parent, new Set());
    this.edges.get(parent)?.add(child);
  }

  pathsTo(name: string): string[] {
    if (this.edges.size === 0) return this.direct.has(name) ? [name] : [];
    const parents = new Map<string, Set<string>>();
    for (const [parent, children] of this.edges) {
      for (const child of children) {
        if (!parents.has(child)) parents.set(child, new Set());
        parents.get(child)?.add(parent);
      }
    }
    const found: string[][] = [];
    const queue: string[][] = [[name]];
    const reached = new Set<string>();
    while (queue.length && found.length < 20) {
      const chain = queue.shift() as string[];
      if (this.direct.has(chain[0]) && !reached.has(chain[0])) {
        reached.add(chain[0]);
        found.push(chain);
      }
      if (chain.length >= 10) continue;
      for (const parent of [...(parents.get(chain[0]) ?? [])].sort()) {
        if (!chain.includes(parent)) queue.push([parent, ...chain]);
      }
    }
    const devRank = (c: string[]) => (this.devDirect.has(c[0]) ? 1 : 0);
    return found
      .sort((a, b) => devRank(a) - devRank(b) || a.length - b.length || a[0].localeCompare(b[0]))
      .map((c) => c.join(ARROW));
  }

  isDevOnly(name: string): boolean {
    if (this.dev.has(name)) return true;
    if (this.direct.has(name)) return this.devDirect.has(name);
    const paths = this.pathsTo(name);
    return paths.length > 0 && paths.every((p) => this.devDirect.has(p.split(ARROW)[0]));
  }
}

const normPy = (name: string) => name.replace(/[-_.]+/g, "-").toLowerCase();
const lineOf = (text: string, needle: string) => {
  const i = text.indexOf(needle);
  return i < 0 ? 1 : text.slice(0, i).split("\n").length;
};

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

function packageJsonDirect(dir: string, graph: DependencyGraph): void {
  const manifest = readJson(join(dir, "package.json")) as Record<string, Record<string, string>> | undefined;
  if (!manifest || typeof manifest !== "object") return;
  for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
    for (const name of Object.keys(manifest[section] ?? {})) {
      graph.direct.add(name);
      if (section === "devDependencies") graph.devDirect.add(name);
    }
  }
}

// ── Minimal TOML: the [[package]] tables of Cargo.lock, poetry.lock and uv.lock ─────────────

interface TomlPackage {
  name?: string;
  version?: string;
  source?: string;
  category?: string;
  deps: string[];
  devDeps: string[];
  line: number;
}

/** "time", "time 0.1.43 (registry+…)" or { name = "x", … } -> the package name. */
function depName(item: string): string | undefined {
  const named = /name\s*=\s*"([^"]+)"/.exec(item);
  if (named) return named[1];
  return /"([^"\s]+)/.exec(item)?.[1];
}

function tomlPackages(text: string): TomlPackage[] {
  const out: TomlPackage[] = [];
  let current: TomlPackage | undefined;
  let table = "";
  let arrayKey = "";
  const lines = text.split("\n");
  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (line === "[[package]]") {
      current = { deps: [], devDeps: [], line: index + 1 };
      out.push(current);
      table = "";
      arrayKey = "";
      return;
    }
    if (!current) return;
    const header = /^\[{1,2}([^\]]+)\]{1,2}$/.exec(line);
    if (header) {
      table = header[1].startsWith("package.") ? header[1].slice("package.".length) : "<other>";
      arrayKey = "";
      if (table === "<other>") current = undefined;
      return;
    }
    if (arrayKey) {
      const dep = depName(line);
      if (dep) (arrayKey === "dependencies" ? current.deps : current.devDeps).push(dep);
      if (line.startsWith("]")) arrayKey = "";
      return;
    }
    const kv = /^([\w.-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) return;
    const [, key, value] = kv;
    if (table === "dependencies") {
      current.deps.push(key);
      return;
    }
    if (table.startsWith("dev-dependencies")) {
      for (const m of value.matchAll(/name\s*=\s*"([^"]+)"/g)) current.devDeps.push(m[1]);
      if (value.startsWith("[") && !value.endsWith("]")) arrayKey = "dev-dependencies";
      return;
    }
    if (table === "source") {
      current.source = `${current.source ?? ""} ${key}`;
      return;
    }
    if (table) return;
    const str = /^"([^"]*)"/.exec(value);
    if (key === "name" && str) current.name = str[1];
    else if (key === "version" && str) current.version = str[1];
    else if (key === "category" && str) current.category = str[1];
    else if (key === "source") current.source = value;
    else if (key === "dependencies" || key === "dev-dependencies") {
      const target = key === "dependencies" ? current.deps : current.devDeps;
      if (!value.startsWith("[")) return;
      const items = value.slice(1, value.endsWith("]") ? -1 : undefined);
      for (const item of items.split(/,(?![^{]*\})/)) {
        const dep = depName(item);
        if (dep) target.push(dep);
      }
      if (!value.endsWith("]")) arrayKey = key;
    }
  });
  return out;
}

// ── Readers: text in, packages + graph out ───────────────────────────────────────────────────

interface Parsed {
  packages: Pkg[];
  graph: DependencyGraph;
}
type Reader = (text: string, dir: string) => Parsed;

const YARN_HEADER = /^"?((?:@[^@/\s"]+\/)?[^@\s"]+)@/;

function yarnLock(text: string, dir: string): Parsed {
  const graph = new DependencyGraph();
  packageJsonDirect(dir, graph);
  const packages: Pkg[] = [];
  let name: string | undefined;
  let inDeps = false;
  text.split("\n").forEach((line, i) => {
    if (!line || line.startsWith("#")) return;
    if (!/^\s/.test(line)) {
      inDeps = false;
      const first = line.split(",")[0];
      name = /@(?:workspace|link|file|portal|patch):/.test(first) || line.startsWith("__metadata")
        ? undefined
        : YARN_HEADER.exec(first)?.[1];
      return;
    }
    if (!name) return;
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (version) {
      packages.push({ ecosystem: "npm", name, version: version[1], line: i + 1 });
      return;
    }
    if (/^\s{2}(?:dependencies|optionalDependencies):?\s*$/.test(line)) {
      inDeps = true;
      return;
    }
    if (inDeps) {
      const dep = /^\s{4}"?((?:@[^@/\s"]+\/)?[^@\s":]+)"?:?\s/.exec(line);
      if (dep) graph.addEdge(name, dep[1]);
      else inDeps = false;
    }
  });
  return { packages, graph };
}

function pnpmLock(text: string, dir: string): Parsed {
  const graph = new DependencyGraph();
  packageJsonDirect(dir, graph);
  const packages: Pkg[] = [];
  let section = "";
  let current = "";
  let inDeps = false;
  const seen = new Set<string>();
  text.split("\n").forEach((line, i) => {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, "");
      return;
    }
    if (section !== "packages" && section !== "snapshots") return;
    const key = /^ {2}'?\/?([^'\s][^']*?)'?:\s*$/.exec(line);
    if (key) {
      const spec = key[1].split("(")[0];
      const at = spec.lastIndexOf("@");
      const [pkgName, version] = at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : [spec.slice(0, spec.lastIndexOf("/")), spec.slice(spec.lastIndexOf("/") + 1)];
      current = pkgName;
      inDeps = false;
      if (section === "packages" && /^\d/.test(version) && !seen.has(spec)) {
        seen.add(spec);
        packages.push({ ecosystem: "npm", name: pkgName, version, line: i + 1 });
      }
      return;
    }
    if (/^ {4}(?:dependencies|optionalDependencies):\s*$/.test(line)) {
      inDeps = true;
      return;
    }
    const dep = /^ {6}'?((?:@[^/\s']+\/)?[^:\s']+)'?:/.exec(line);
    if (inDeps && dep && current) graph.addEdge(current, dep[1]);
    else if (!/^ {6}/.test(line)) inDeps = false;
  });
  return { packages, graph };
}

function requirements(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    const pin = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,\\]+)/.exec(line);
    const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line);
    if (name) graph.direct.add(normPy(name[1]));
    if (pin) packages.push({ ecosystem: "PyPI", name: normPy(pin[1]), version: pin[2], line: i + 1 });
  });
  return { packages, graph };
}

function pythonToml(text: string, dir: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  for (const entry of tomlPackages(text)) {
    if (!entry.name) continue;
    const name = normPy(entry.name);
    const src = entry.source ?? "";
    if (/virtual|editable/.test(src)) {
      for (const d of entry.deps) graph.direct.add(normPy(d));
      for (const d of entry.devDeps) {
        graph.direct.add(normPy(d));
        graph.devDirect.add(normPy(d));
      }
      continue;
    }
    if (/\bpath\b/.test(src)) continue;
    if (entry.category === "dev") graph.dev.add(name);
    for (const d of entry.deps) graph.addEdge(name, normPy(d));
    if (entry.version) packages.push({ ecosystem: "PyPI", name, version: entry.version, line: entry.line });
  }
  // Direct dependencies from pyproject.toml (poetry and PEP 621), read loosely.
  try {
    const project = readFileSync(join(dir, "pyproject.toml"), "utf8");
    let table = "";
    for (const raw of project.split("\n")) {
      const line = raw.trim();
      const header = /^\[([^\]]+)\]$/.exec(line);
      if (header) {
        table = header[1];
        continue;
      }
      const dev = /^tool\.poetry\.group\.[\w-]+\.dependencies$/.test(table);
      if (table === "tool.poetry.dependencies" || dev) {
        const key = /^([\w.-]+)\s*=/.exec(line)?.[1];
        if (key && key !== "python") {
          graph.direct.add(normPy(key));
          if (dev) graph.devDirect.add(normPy(key));
        }
      }
      if (table === "project") {
        for (const m of line.matchAll(/"([A-Za-z0-9][A-Za-z0-9._-]*)/g)) {
          if (/dependencies|^"/.test(line)) graph.direct.add(normPy(m[1]));
        }
      }
    }
  } catch {
    // no pyproject.toml
  }
  return { packages, graph };
}

function pipfileLock(text: string, dir: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  const data = JSON.parse(text) as Record<string, Record<string, { version?: string }>>;
  for (const section of ["default", "develop"]) {
    for (const [name, entry] of Object.entries(data[section] ?? {})) {
      const version = entry?.version;
      if (section === "develop" && !(data.default ?? {})[name]) graph.dev.add(normPy(name));
      if (typeof version === "string" && version.startsWith("==")) {
        packages.push({ ecosystem: "PyPI", name: normPy(name), version: version.slice(2), line: lineOf(text, `"${name}"`) });
      }
    }
  }
  try {
    let table = "";
    for (const raw of readFileSync(join(dir, "Pipfile"), "utf8").split("\n")) {
      const line = raw.trim();
      const header = /^\[([^\]]+)\]$/.exec(line);
      if (header) table = header[1];
      const key = /^"?([\w.-]+)"?\s*=/.exec(line)?.[1];
      if (key && (table === "packages" || table === "dev-packages")) {
        graph.direct.add(normPy(key));
        if (table === "dev-packages") graph.devDirect.add(normPy(key));
      }
    }
  } catch {
    // no Pipfile
  }
  return { packages, graph };
}

function goMod(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  let block = "";
  graph.direct.add("stdlib");
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (block) {
      if (line.startsWith(")")) {
        block = "";
        return;
      }
      if (block !== "require") return;
    } else if (/^(require|replace|exclude|retract)\s*\($/.test(line)) {
      block = line.split(/\s/)[0];
      return;
    }
    const toolchain = /^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$/.exec(line);
    if (toolchain) {
      packages.push({ ecosystem: "Go", name: "stdlib", version: toolchain[1], line: i + 1 });
      return;
    }
    if (!block && !line.startsWith("require ")) return;
    const req = /^(?:require\s+)?([^\s()]+\.[^\s()]+)\s+(v\d\S*)/.exec(line);
    if (!req) return;
    packages.push({ ecosystem: "Go", name: req[1], version: req[2].replace(/\+incompatible$/, ""), line: i + 1 });
    if (!line.includes("// indirect")) graph.direct.add(req[1]);
  });
  return { packages, graph };
}

function pubspecLock(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  let name = "";
  let start = 0;
  let entry: Record<string, string> = {};
  const flush = () => {
    if (!name) return;
    const kind = entry.dependency ?? "";
    if (kind.startsWith("direct")) graph.direct.add(name);
    if (kind === "direct dev") graph.devDirect.add(name);
    if (entry.source === "hosted" && entry.version) {
      packages.push({ ecosystem: "Pub", name, version: entry.version, line: start });
    }
  };
  let inPackages = false;
  text.split("\n").forEach((line, i) => {
    if (/^\S/.test(line)) {
      flush();
      name = "";
      inPackages = line.startsWith("packages:");
      return;
    }
    if (!inPackages) return;
    const header = /^ {2}([\w-]+):\s*$/.exec(line);
    if (header) {
      flush();
      name = header[1];
      start = i + 1;
      entry = {};
      return;
    }
    const kv = /^ {4}(dependency|source|version):\s*"?([^"]*)"?\s*$/.exec(line);
    if (kv) entry[kv[1]] = kv[2];
  });
  flush();
  return { packages, graph };
}

function cargoLock(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  const entries = tomlPackages(text);
  const members = new Set(entries.filter((e) => !e.source).map((e) => e.name));
  for (const e of entries) {
    for (const dep of e.deps) {
      if (members.has(e.name)) graph.direct.add(dep);
      else if (e.name) graph.addEdge(e.name, dep);
    }
    if (e.name && e.version && (e.source ?? "").includes("registry+")) {
      packages.push({ ecosystem: "crates.io", name: e.name, version: e.version, line: e.line });
    }
  }
  return { packages, graph };
}

function gemfileLock(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  let section = "";
  let current = "";
  text.split("\n").forEach((line, i) => {
    if (line && !/^\s/.test(line)) {
      section = line.trim();
      return;
    }
    if (section === "GEM") {
      const spec = /^ {4}([A-Za-z0-9][\w.-]*) \(([^)]+)\)$/.exec(line);
      const dep = /^ {6}([\w.-]+)/.exec(line);
      if (spec) {
        current = spec[1];
        const version = spec[2].replace(/-(?:[a-z]|x86|x64|java|universal).*$/, "");
        packages.push({ ecosystem: "RubyGems", name: spec[1], version, line: i + 1 });
      } else if (dep && current) graph.addEdge(current, dep[1]);
    } else if (section === "DEPENDENCIES") {
      const dep = /^ {2}([\w.-]+)/.exec(line);
      if (dep) graph.direct.add(dep[1]);
    }
  });
  return { packages, graph };
}

function nugetLock(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  const data = JSON.parse(text) as { dependencies?: Record<string, Record<string, { type?: string; resolved?: string; dependencies?: Record<string, string> }>> };
  for (const deps of Object.values(data.dependencies ?? {})) {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (!entry || entry.type === "Project") continue;
      if (entry.type === "Direct") graph.direct.add(name);
      for (const child of Object.keys(entry.dependencies ?? {})) graph.addEdge(name, child);
      if (entry.resolved) packages.push({ ecosystem: "NuGet", name, version: entry.resolved, line: lineOf(text, `"${name}"`) });
    }
  }
  return { packages, graph };
}

function composerLock(text: string, dir: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  const data = JSON.parse(text) as Record<string, Array<{ name?: string; version?: string; require?: Record<string, string> }>>;
  for (const section of ["packages", "packages-dev"]) {
    for (const entry of data[section] ?? []) {
      if (!entry?.name || !entry.version) continue;
      if (section === "packages-dev") graph.dev.add(entry.name);
      for (const child of Object.keys(entry.require ?? {})) if (child.includes("/")) graph.addEdge(entry.name, child);
      packages.push({ ecosystem: "Packagist", name: entry.name, version: entry.version.replace(/^v(?=\d)/, ""), line: lineOf(text, `"${entry.name}"`) });
    }
  }
  const manifest = readJson(join(dir, "composer.json")) as Record<string, Record<string, string>> | undefined;
  for (const section of ["require", "require-dev"]) {
    for (const name of Object.keys(manifest?.[section] ?? {})) {
      if (!name.includes("/")) continue;
      graph.direct.add(name);
      if (section === "require-dev") graph.devDirect.add(name);
    }
  }
  return { packages, graph };
}

function pomXml(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  const props = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(text)?.[1] ?? "";
  for (const m of propsBlock.matchAll(/<([\w.-]+)>([^<]+)<\/\1>/g)) props.set(m[1], m[2].trim());
  const resolve = (v: string) => v.replace(/\$\{([^}]+)\}/g, (_, k: string) => props.get(k) ?? `\${${k}}`);
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = m[1];
    const tag = (t: string) => new RegExp(`<${t}>\\s*([^<]+?)\\s*</${t}>`).exec(body)?.[1];
    const group = tag("groupId");
    const artifact = tag("artifactId");
    const raw = tag("version");
    if (!group || !artifact || !raw) continue;
    const version = resolve(raw);
    if (!/^[\w.+-]+$/.test(version) || /SNAPSHOT/i.test(version)) continue;
    const name = `${group}:${artifact}`;
    graph.direct.add(name);
    if (tag("scope") === "test") graph.devDirect.add(name);
    packages.push({ ecosystem: "Maven", name, version, line: lineOf(text, `<artifactId>${artifact}</artifactId>`) });
  }
  return { packages, graph };
}

function gradleLockfile(text: string): Parsed {
  const graph = new DependencyGraph();
  const packages: Pkg[] = [];
  text.split("\n").forEach((line, i) => {
    const m = /^([\w.-]+):([\w.-]+):([\w.+-]+)=(.*)$/.exec(line.trim());
    if (!m) return;
    const name = `${m[1]}:${m[2]}`;
    if (!/(?:compile|runtime)Classpath/.test(m[4])) graph.dev.add(name);
    packages.push({ ecosystem: "Maven", name, version: m[3], line: i + 1 });
  });
  return { packages, graph };
}

const READERS: Record<string, Reader> = {
  "yarn.lock": yarnLock,
  "pnpm-lock.yaml": pnpmLock,
  "poetry.lock": pythonToml,
  "uv.lock": pythonToml,
  "Pipfile.lock": pipfileLock,
  "go.mod": goMod,
  "pubspec.lock": pubspecLock,
  "Cargo.lock": cargoLock,
  "Gemfile.lock": gemfileLock,
  "gems.locked": gemfileLock,
  "packages.lock.json": nugetLock,
  "composer.lock": composerLock,
  "pom.xml": pomXml,
  "gradle.lockfile": gradleLockfile,
};

export function readerFor(name: string): Reader | undefined {
  if (READERS[name]) return READERS[name];
  if (name.startsWith("requirements") && name.endsWith(".txt")) return requirements;
  return undefined;
}

/** Packages and dependency graph of one lockfile (empty when it can't be read). */
export function readLockfile(path: string): Parsed {
  const reader = readerFor(basename(path));
  if (!reader) return { packages: [], graph: new DependencyGraph() };
  try {
    return reader(readFileSync(path, "utf8"), dirname(path));
  } catch {
    return { packages: [], graph: new DependencyGraph() };
  }
}

export function findLockfiles(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 8) return;
    let entries: string[];
    try {
      entries = readdirSync(dir).sort();
    } catch {
      return;
    }
    for (const name of entries) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      try {
        const st = lstatSync(full);
        if (st.isDirectory() && !st.isSymbolicLink()) walk(full, depth + 1);
        else if (st.isFile() && readerFor(name)) found.push(full);
      } catch {
        // unreadable entry
      }
    }
  };
  walk(root, 0);
  return found;
}

// ── OSV ─────────────────────────────────────────────────────────────────────────────────────

export interface OsvRecord {
  id?: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{ package?: { name?: string }; ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}

export interface OsvClient {
  queryIds(packages: Pkg[]): Promise<Map<Pkg, string[]>>;
  details(ids: string[]): Promise<Map<string, OsvRecord>>;
}

export const osvClient: OsvClient = {
  async queryIds(packages) {
    const out = new Map<Pkg, string[]>();
    for (let start = 0; start < packages.length; start += BATCH) {
      const batch = packages.slice(start, start + BATCH);
      const response = await fetch(`${OSV}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "argus-codescan" },
        body: JSON.stringify({
          queries: batch.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })),
        }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) throw new Error(`OSV returned ${response.status}`);
      const data = (await response.json()) as { results?: Array<{ vulns?: Array<{ id?: string }> }> };
      (data.results ?? []).forEach((r, i) => {
        const ids = [...new Set((r?.vulns ?? []).map((v) => v.id).filter((id): id is string => !!id))].sort();
        if (ids.length) out.set(batch[i], ids);
      });
    }
    return out;
  },
  async details(ids) {
    const out = new Map<string, OsvRecord>();
    const queue = [...ids];
    const worker = async () => {
      for (let id = queue.shift(); id; id = queue.shift()) {
        try {
          const r = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, {
            headers: { "User-Agent": "argus-codescan" },
            signal: AbortSignal.timeout(20_000),
          });
          if (r.ok) out.set(id, (await r.json()) as OsvRecord);
        } catch {
          // one failed lookup leaves that advisory out
        }
      }
    };
    await Promise.all(Array.from({ length: 8 }, worker));
    return out;
  },
};

const SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", moderate: "moderate", medium: "moderate", low: "low" };
const RANK: Record<Severity, number> = { critical: 0, high: 1, moderate: 2, low: 3, info: 4 };
const LABELS: Record<string, string> = {
  npm: "npm", PyPI: "Python", Go: "Go", Pub: "Dart / Flutter", "crates.io": "Rust",
  RubyGems: "Ruby", NuGet: ".NET", Packagist: "PHP", Maven: "Java",
};

const versionKey = (v: string) => (v.match(/\d+/g) ?? []).slice(0, 4).map(Number);
export function compareVersions(a: string, b: string): number {
  const [x, y] = [versionKey(a), versionKey(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  }
  return 0;
}

function severityOf(record: OsvRecord, related: Map<string, OsvRecord>): Severity {
  for (const r of [record, ...(record.aliases ?? []).map((a) => related.get(a) ?? {})]) {
    const label = String(r.database_specific?.severity ?? "").toLowerCase();
    if (SEVERITY[label]) return SEVERITY[label];
  }
  return "high";
}

function nearestFix(record: OsvRecord, pkg: Pkg): string | undefined {
  const fixed = new Set<string>();
  for (const affected of record.affected ?? []) {
    if (affected.package?.name && affected.package.name !== pkg.name) continue;
    for (const range of affected.ranges ?? []) for (const e of range.events ?? []) if (e.fixed) fixed.add(e.fixed);
  }
  const newer = [...fixed].filter((v) => compareVersions(v, pkg.version) > 0).sort(compareVersions);
  return newer[0];
}

const isToolchain = (p: Pkg) => p.ecosystem === "Go" && p.name === "stdlib";

/** How to move to `target` (the version that fixes every advisory) in this ecosystem. */
export function fixAdvice(pkg: Pkg, target: string, paths: string[], unfixed = 0): string {
  const { name } = pkg;
  const still = unfixed ? ` ${unfixed} ${unfixed === 1 ? "advisory has" : "advisories have"} no fix yet.` : "";
  if (!target) return `No patched version of ${name} is published yet. Check the advisories for workarounds and update when a fix is released.`;
  if (isToolchain(pkg)) return `Build with Go ${target} or later (set \`toolchain go${target}\` in go.mod).${still}`;
  const goVersion = `v${target.replace(/^v/, "")}`;
  if (paths.length && paths.every((p) => p.includes(ARROW))) {
    const pin: Record<string, string> = {
      npm: `add "overrides": {"${name}": "${target}"} to package.json`,
      PyPI: `add ${name}>=${target} to your requirements or constraints`,
      Go: `run go get ${name}@${goVersion} and go mod tidy`,
      Pub: `add ${name}: ^${target} under dependency_overrides in pubspec.yaml`,
      "crates.io": `run cargo update -p ${name} --precise ${target}`,
      RubyGems: `run bundle update ${name}`,
      NuGet: `add <PackageReference Include="${name}" Version="${target}" />`,
      Packagist: `run composer update ${name} --with-dependencies`,
      Maven: `add ${name}:${target} to <dependencyManagement> (or a Gradle constraint)`,
    };
    return `Upgrade ${name} to ${target}: update ${paths[0].split(ARROW)[0]}, which brings it in, or ${pin[pkg.ecosystem] ?? `upgrade ${name}`}.${still}`;
  }
  const how: Record<string, string> = {
    npm: `npm install ${name}@${target}`,
    PyPI: `set ${name}>=${target} in your requirements, pyproject or Pipfile and re-lock`,
    Go: `go get ${name}@${goVersion} and go mod tidy`,
    Pub: `set ${name}: ^${target} in pubspec.yaml, then flutter pub upgrade ${name}`,
    "crates.io": `set ${name} = "${target}" in Cargo.toml, then cargo update -p ${name}`,
    RubyGems: `bundle update ${name}`,
    NuGet: `update the PackageReference for ${name} to ${target}`,
    Packagist: `composer require ${name}:^${target}`,
    Maven: `set the version of ${name} to ${target} in your build file`,
  };
  return `Upgrade ${name} to ${target} (${how[pkg.ecosystem] ?? `upgrade ${name}`}).${still}`;
}

function toFinding(pkg: Pkg, advisories: [string, OsvRecord][], related: Map<string, OsvRecord>, lockfile: string, graph: DependencyGraph): Finding {
  const scored = advisories
    .map(([id, record]) => ({ id, record, severity: severityOf(record, related) }))
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.id.localeCompare(b.id));
  const top = scored[0];
  const fixes = scored.map((s) => nearestFix(s.record, pkg));
  const unfixed = fixes.filter((f) => !f).length;
  const target = fixes.filter((f): f is string => !!f).sort(compareVersions).pop() ?? "";
  const paths = isToolchain(pkg) ? [] : graph.pathsTo(pkg.name);
  const dev = graph.isDevOnly(pkg.name);
  const severity = dev ? downgrade(top.severity) : top.severity;
  let subject: string;
  let how: string;
  if (isToolchain(pkg)) {
    subject = `Go toolchain ${pkg.version}`;
    how = "toolchain in go.mod";
  } else {
    subject = `${LABELS[pkg.ecosystem] ?? pkg.ecosystem} package ${pkg.name} ${pkg.version}`;
    how = graph.direct.has(pkg.name) ? "direct dependency" : paths.length ? `via ${paths[0].split(ARROW).slice(0, -1).join(ARROW)}` : "transitive dependency";
  }
  const summary = top.record.summary?.trim() || `Known vulnerability ${top.id}`;
  const label = isToolchain(pkg) ? "Go toolchain" : pkg.name;
  const ids = scored.map((s) => s.id);
  const shown = ids.slice(0, 5).join(", ") + (ids.length > 5 ? ` and ${ids.length - 5} more` : "");
  return {
    title: ids.length === 1 ? `${label}: ${summary}` : `${label}: ${ids.length} known vulnerabilities`,
    severity,
    tool: TOOL,
    file: lockfile,
    package: pkg.name,
    version: pkg.version,
    ruleId: top.id,
    confidence: "high",
    ...(dev ? { context: "dev-dependency" as const } : {}),
    description: `[${dev ? "dev" : "runtime"} dependency] ${subject} (${how}): ${shown}${ids.length > 1 ? `. Most severe: ${summary}` : ""}`,
    url: `https://osv.dev/vulnerability/${top.id}`,
    paths,
    fix: fixAdvice(pkg, target, paths, unfixed),
  };
}

export function networkDisabled(): boolean {
  return ["1", "true", "yes"].includes((process.env.ARGUS_NO_NETWORK ?? "").trim().toLowerCase());
}

export async function runOsvDependencyCheck(target: string, client: OsvClient = osvClient): Promise<ScanResult> {
  const result: ScanResult = { tool: TOOL, scanType: "sca", target, findings: [], errors: [], projects: [] };
  let root = target;
  let lockfiles: string[];
  try {
    if (lstatSync(target).isDirectory()) lockfiles = findLockfiles(target);
    else {
      root = dirname(target);
      lockfiles = readerFor(basename(target)) ? [target] : [];
    }
  } catch {
    return result;
  }
  const rel = (p: string) => relative(root, p).split(sep).join("/");
  const parsed = new Map<string, Parsed>();
  const where = new Map<string, { pkg: Pkg; lockfiles: string[] }>();
  for (const file of lockfiles) {
    const lock = readLockfile(file);
    if (!lock.packages.length) continue;
    parsed.set(rel(file), lock);
    result.projects?.push(file);
    for (const pkg of lock.packages) {
      const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
      if (!where.has(key)) where.set(key, { pkg, lockfiles: [] });
      where.get(key)?.lockfiles.push(rel(file));
    }
  }
  if (!where.size) return result;
  if (networkDisabled()) {
    result.notes = [...(result.notes ?? []), "Dependency check against OSV skipped: network disabled (ARGUS_NO_NETWORK / --no-network)."];
    return result;
  }
  try {
    const unique = [...where.values()].map((w) => w.pkg);
    const idsByPkg = await client.queryIds(unique);
    for (const [pkg, ids] of idsByPkg) idsByPkg.set(pkg, ids.filter((i) => !i.startsWith("MAL-")));
    const allIds = [...new Set([...idsByPkg.values()].flat())].sort();
    const lookups = allIds.slice(0, MAX_DETAILS);
    const details = await client.details(lookups);
    const missing = [...new Set([...details.values()].filter((r) => !r.database_specific?.severity).flatMap((r) => (r.aliases ?? []).filter((a) => a.startsWith("GHSA-") && !details.has(a))))]
      .sort()
      .slice(0, Math.max(0, MAX_DETAILS - lookups.length));
    const related = new Map([...details, ...(missing.length ? await client.details(missing) : [])]);
    if (allIds.length > lookups.length) result.errors.push(`${allIds.length - lookups.length} more advisories were not looked up (limit ${MAX_DETAILS})`);
    for (const [pkg, ids] of idsByPkg) {
      const advisories = ids.filter((i) => details.has(i)).map((i): [string, OsvRecord] => [i, details.get(i) as OsvRecord]);
      if (!advisories.length) continue;
      const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
      for (const lockfile of where.get(key)?.lockfiles ?? []) {
        const lock = parsed.get(lockfile) as Parsed;
        const line = lock.packages.find((p) => p.name === pkg.name && p.version === pkg.version)?.line;
        result.findings.push({ ...toFinding(pkg, advisories, related, lockfile, lock.graph), line });
      }
    }
  } catch (err) {
    result.errors.push(`OSV dependency check skipped: network unavailable (${err instanceof Error ? err.message : String(err)})`);
    return result;
  }
  result.findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || (a.package ?? "").localeCompare(b.package ?? ""));
  return result;
}
