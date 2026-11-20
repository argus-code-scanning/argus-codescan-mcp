/**
 * Terraform dependencies: how modules and providers are pinned. Same checks and ids as
 * argus-scan (Python) argus/tools/terraform_deps.py:
 *
 * - tf-module-insecure-source (high): module downloaded over http:// or git:// (unencrypted)
 * - tf-module-git-unpinned (moderate): git module without ?ref=, or on a branch
 * - tf-module-registry-unpinned (moderate): registry module without a version
 * - tf-provider-unpinned (low): required_providers entry without a version constraint
 * - tf-lockfile-missing (low): root module with no .terraform.lock.hcl
 */

import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { downgrade, pathContext } from "./noise.js";
import type { Finding, ScanResult, Severity } from "./types.js";

const TOOL = "terraform-deps";
const BRANCHES = new Set(["main", "master", "develop", "dev", "trunk", "head", "latest", "staging", "prod"]);
const BLOCK = /^[ \t]*(module|terraform)\b[ \t]*(?:"([^"]+)")?[ \t]*\{/gm;
const ATTR = /^\s*(source|version)\s*=\s*"([^"]*)"/;
const ROOT_MARKER = /^\s*(?:backend\s+"[\w-]+"|cloud|provider\s+"[\w-]+")\s*\{/m;
const SKIP_DIRS = new Set(["node_modules", ".git", ".terraform", "dist", "build", "vendor", "coverage"]);

export interface TerraformIssue {
  rule: string;
  severity: Severity;
  title: string;
  line: number;
  fix: string;
}

/** Index just past the brace that closes the block opening at `start` (a "{"). */
function blockEnd(text: string, start: number): number {
  let depth = 0;
  let quote = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === '"') quote = false;
    } else if (ch === '"') {
      quote = true;
    } else if (ch === "#" || text.startsWith("//", i)) {
      const nl = text.indexOf("\n", i);
      if (nl < 0) return text.length;
      i = nl - 1;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return text.length;
}

function topLevelAttrs(body: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  let depth = 0;
  for (const line of body.split("\n")) {
    if (depth === 0) {
      const m = ATTR.exec(line);
      if (m && attrs[m[1]] === undefined) attrs[m[1]] = m[2];
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
  }
  return attrs;
}

const lineAt = (text: string, index: number) => text.slice(0, index).split("\n").length;

function moduleIssue(name: string, source: string, version: string | undefined, line: number): TerraformIssue | undefined {
  const lowered = source.toLowerCase();
  if (!source || source.startsWith("./") || source.startsWith("../")) return undefined;
  if (/^(?:git::)?(?:http|git):\/\//.test(lowered)) {
    return {
      rule: "tf-module-insecure-source",
      severity: "high",
      title: `Module "${name}" is downloaded without encryption (${source.split("?")[0]})`,
      line,
      fix: "Use an https:// or ssh source so the module can't be swapped in transit.",
    };
  }
  const isGit =
    /^(?:git::|git@|github\.com\/|bitbucket\.org\/)/.test(lowered) || (lowered.includes(".git") && lowered.includes("://"));
  if (isGit) {
    const ref = /[?&]ref=([^&]+)/.exec(source);
    let problem: string;
    if (!ref) problem = "has no ?ref=, so it follows the default branch";
    else if (BRANCHES.has(ref[1].toLowerCase())) problem = `uses the branch '${ref[1]}', which can change`;
    else return undefined;
    return {
      rule: "tf-module-git-unpinned",
      severity: "moderate",
      title: `Git module "${name}" ${problem}`,
      line,
      fix: "Pin it to a commit SHA (?ref=<40-character SHA>) or at least a release tag.",
    };
  }
  if (/^(?:[\w.-]+\/)?[\w-]+\/[\w-]+\/[\w-]+(?:\/\/.*)?$/.test(source) && !source.includes("://") && !version) {
    return {
      rule: "tf-module-registry-unpinned",
      severity: "moderate",
      title: `Registry module "${name}" (${source}) has no version, so init takes the latest`,
      line,
      fix: 'Add version = "x.y.z" (an exact version) to the module block.',
    };
  }
  return undefined;
}

function providerIssues(block: string, offsetLine: number): TerraformIssue[] {
  const m = /\brequired_providers\s*\{/.exec(block);
  if (!m) return [];
  const start = m.index + m[0].length - 1;
  const body = block.slice(start + 1, blockEnd(block, start) - 1);
  const issues: TerraformIssue[] = [];
  for (const entry of body.matchAll(/^\s*([\w-]+)\s*=\s*(\{|")/gm)) {
    if (entry[2] === '"') continue; // legacy  aws = "~> 4.0"
    const brace = (entry.index ?? 0) + entry[0].length - 1;
    const spec = body.slice(brace, blockEnd(body, brace));
    if (/(?:^|[\s,{])version\s*=/.test(spec)) continue;
    const source = /source\s*=\s*"([^"]+)"/.exec(spec);
    const nameStart = (entry.index ?? 0) + entry[0].indexOf(entry[1]);
    issues.push({
      rule: "tf-provider-unpinned",
      severity: "low",
      title: `Provider ${source ? source[1] : entry[1]} has no version constraint`,
      line: offsetLine + (block.slice(0, start + 1 + nameStart).match(/\n/g) ?? []).length,
      fix: 'Add version = "~> x.y" so a new major release is not picked up by surprise.',
    });
  }
  return issues;
}

/** Issues in one .tf file, and whether it looks like a root module (backend, cloud, provider). */
export function checkTerraformFile(text: string): { issues: TerraformIssue[]; rootModule: boolean } {
  const issues: TerraformIssue[] = [];
  for (const match of text.matchAll(BLOCK)) {
    const keywordAt = (match.index ?? 0) + match[0].indexOf(match[1]);
    const openBrace = (match.index ?? 0) + match[0].length - 1;
    const end = blockEnd(text, openBrace);
    const line = lineAt(text, keywordAt);
    if (match[1] === "module") {
      const attrs = topLevelAttrs(text.slice(openBrace + 1, end - 1));
      const issue = moduleIssue(match[2] ?? "", attrs.source ?? "", attrs.version, line);
      if (issue) issues.push(issue);
    } else {
      issues.push(...providerIssues(text.slice(keywordAt, end), line));
    }
  }
  return { issues, rootModule: ROOT_MARKER.test(text) };
}

function findTfFiles(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 12) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      try {
        const st = lstatSync(full);
        if (st.isDirectory() && !st.isSymbolicLink()) walk(full, depth + 1);
        else if (st.isFile() && name.endsWith(".tf")) found.push(full);
      } catch {
        // unreadable entry
      }
    }
  };
  walk(root, 0);
  return found.sort();
}

function toFinding(issue: TerraformIssue, file: string): Finding {
  const context = pathContext(file);
  return {
    title: issue.title,
    severity: context ? downgrade(issue.severity) : issue.severity,
    tool: TOOL,
    file,
    line: issue.line || undefined,
    ruleId: issue.rule,
    confidence: "high",
    description: `fix: ${issue.fix}`,
    ...(context ? { context } : {}),
  };
}

export async function runTerraformDependencyCheck(target: string): Promise<ScanResult> {
  const result: ScanResult = { tool: TOOL, scanType: "sca", target, findings: [], errors: [], projects: [] };
  let root = target;
  let files: string[];
  try {
    if (lstatSync(target).isDirectory()) files = findTfFiles(target);
    else {
      root = dirname(target);
      files = target.endsWith(".tf") ? [target] : [];
    }
  } catch {
    return result;
  }
  const rel = (p: string) => relative(root, p).split(sep).join("/") || ".";
  const rootDirs = new Set<string>();
  for (const file of files) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const { issues, rootModule } = checkTerraformFile(text);
    if (rootModule) rootDirs.add(dirname(file));
    for (const issue of issues) result.findings.push(toFinding(issue, rel(file)));
  }
  for (const dir of [...rootDirs].sort()) {
    result.projects?.push(dir);
    if (existsSync(join(dir, ".terraform.lock.hcl"))) continue;
    const where = rel(dir);
    result.findings.push(
      toFinding(
        {
          rule: "tf-lockfile-missing",
          severity: "low",
          title: `No .terraform.lock.hcl in ${where}: provider versions and checksums are not locked`,
          line: 0,
          fix: "Run terraform init and commit .terraform.lock.hcl, so every run uses the same provider builds (checked against their hashes).",
        },
        where === "." ? ".terraform.lock.hcl" : `${where}/.terraform.lock.hcl`,
      ),
    );
  }
  if (files.length && !result.projects?.length) result.projects?.push(root);
  return result;
}
