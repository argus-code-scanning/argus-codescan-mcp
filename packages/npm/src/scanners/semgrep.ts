import { execa } from "execa";
import { ensureOpengrepBinary, opengrepCachePath } from "./opengrep-installer.js";
import { mapSemgrepSeverity } from "./severity.js";
import { isToolAvailable } from "./tools.js";
import type { Finding, ScanResult } from "./types.js";

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: { cwe?: string[]; owasp?: string[] };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: Array<{ message?: string }>;
}

export interface ResolvedSastEngine {
  cmd: string;
  args: string[];
  tool: "semgrep" | "opengrep";
}

export async function resolveSemgrepCommand(): Promise<ResolvedSastEngine | null> {
  if (await isToolAvailable("semgrep")) {
    return { cmd: "semgrep", args: [], tool: "semgrep" };
  }

  if (await isToolAvailable("opengrep")) {
    return { cmd: "opengrep", args: [], tool: "opengrep" };
  }

  const cached = opengrepCachePath();
  if (cached) {
    const downloaded = await ensureOpengrepBinary();
    if (downloaded) {
      return { cmd: downloaded, args: [], tool: "opengrep" };
    }
  }

  if (await isToolAvailable("uvx")) {
    return { cmd: "uvx", args: ["semgrep"], tool: "semgrep" };
  }

  if (await isToolAvailable("python3")) {
    return { cmd: "python3", args: ["-m", "semgrep"], tool: "semgrep" };
  }
  if (await isToolAvailable("python")) {
    return { cmd: "python", args: ["-m", "semgrep"], tool: "semgrep" };
  }

  return null;
}

function parseSemgrepJson(stdout: string, result: ScanResult, tool: string): void {
  let data: SemgrepOutput = {};
  try {
    data = JSON.parse(stdout || "{}") as SemgrepOutput;
  } catch {
    result.errors.push("Failed to parse semgrep JSON output");
    return;
  }

  for (const err of data.errors ?? []) {
    if (err.message) result.errors.push(err.message);
  }

  for (const r of data.results ?? []) {
    const ruleId = r.check_id ?? "unknown";
    result.findings.push({
      title: r.extra?.message ?? ruleId,
      severity: mapSemgrepSeverity(r.extra?.severity),
      tool,
      file: r.path,
      line: r.start?.line,
      ruleId,
      description: [
        r.extra?.metadata?.cwe?.length ? `CWE: ${r.extra.metadata.cwe.join(", ")}` : "",
        r.extra?.metadata?.owasp?.length ? `OWASP: ${r.extra.metadata.owasp.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join(" | "),
    });
  }
}

export async function runSemgrepSast(target: string, timeoutMs = 300_000): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "semgrep",
    scanType: "sast",
    target,
    findings: [],
    errors: [],
  };

  const resolved = await resolveSemgrepCommand();
  if (!resolved) {
    result.errors.push(
      "Deep SAST engine unavailable on this platform.\n" +
        "  Built-in argus-native + eslint-security still ran.\n" +
        "  Optional: pip install semgrep  OR  install opengrep from github.com/opengrep/opengrep",
    );
    return result;
  }

  result.tool = resolved.tool;

  const baseArgs = ["scan", "--config", "auto", "--json", "--quiet", target];
  const cmd = resolved.cmd;
  const args = [...resolved.args, ...baseArgs];

  try {
    const { stdout, stderr, exitCode } = await execa(cmd, args, {
      timeout: timeoutMs,
      reject: false,
    });

    parseSemgrepJson(stdout, result, resolved.tool);

    if (stderr && result.findings.length === 0 && result.errors.length === 0) {
      result.errors.push(stderr.slice(0, 400));
    }

    // Semgrep/Opengrep exit 1 when findings exist — that is OK
    if (exitCode !== 0 && exitCode !== 1 && result.findings.length === 0) {
      result.errors.push(`${resolved.tool} exited with code ${exitCode}`);
    }
  } catch (err) {
    result.errors.push(err instanceof Error ? err.message : String(err));
  }

  return result;
}
