import { execa } from "execa";
import { readFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { mapGitleaksSeverity } from "./severity.js";
import { isToolAvailable } from "./tools.js";
import type { Finding, ScanResult } from "./types.js";

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: Finding["severity"] }> = [
  {
    name: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: "critical",
  },
  {
    name: "GitHub Token",
    pattern: /ghp_[a-zA-Z0-9]{36,}/,
    severity: "critical",
  },
  {
    name: "Generic API Key",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
    severity: "high",
  },
  {
    name: "Private Key Block",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical",
  },
];

const SCAN_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".php", ".go", ".rb",
  ".env", ".yaml", ".yml", ".json", ".xml", ".properties",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", "__pycache__",
]);

interface GitleaksFinding {
  RuleID?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Description?: string;
}

function walkFiles(dir: string, base: string, out: string[], depth = 0): void {
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
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walkFiles(full, base, out, depth + 1);
    } else {
      const ext = name.includes(".") ? name.slice(name.lastIndexOf(".")) : "";
      if (SCAN_EXTENSIONS.has(ext) || name === ".env") {
        out.push(full);
      }
    }
  }
}

async function runPatternSecrets(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "argus-secrets",
    scanType: "secrets",
    target,
    findings: [],
    errors: [],
  };

  const files: string[] = [];
  walkFiles(target, target, files);

  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relative(target, file);
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        if (pattern.test(lines[i])) {
          result.findings.push({
            title: `Possible secret: ${name}`,
            severity,
            tool: "argus-secrets",
            file: rel,
            line: i + 1,
            ruleId: name,
            description: "Pattern-based detection — verify and rotate if real",
          });
        }
      }
    }
  }

  return result;
}

export async function runGitleaksSecrets(target: string, timeoutMs = 300_000): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "gitleaks",
    scanType: "secrets",
    target,
    findings: [],
    errors: [],
  };

  if (!(await isToolAvailable("gitleaks"))) {
    result.errors.push(
      "gitleaks not installed — using built-in pattern scan.\n" +
        "  Optional: install gitleaks from https://github.com/gitleaks/gitleaks/releases",
    );
    return result;
  }

  try {
    const reportFile = join(tmpdir(), `argus-gitleaks-${Date.now()}.json`);
    const { exitCode } = await execa(
      "gitleaks",
      [
        "detect",
        "--source",
        target,
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        reportFile,
      ],
      { timeout: timeoutMs, reject: false },
    );

    let raw: string;
    try {
      raw = readFileSync(reportFile, "utf8");
      unlinkSync(reportFile);
    } catch {
      if (exitCode === 0 || exitCode === 1) return result;
      result.errors.push(`gitleaks exited with code ${exitCode}`);
      return result;
    }

    if (!raw.trim()) return result;

    let leaks: GitleaksFinding[];
    try {
      leaks = JSON.parse(raw) as GitleaksFinding[];
    } catch {
      result.errors.push("Failed to parse gitleaks output");
      return result;
    }

    for (const leak of leaks) {
      result.findings.push({
        title: leak.Description ?? leak.RuleID ?? "Secret detected",
        severity: mapGitleaksSeverity(leak.RuleID ?? ""),
        tool: "gitleaks",
        file: leak.File,
        line: leak.StartLine,
        ruleId: leak.RuleID,
        description: leak.Secret ? "Secret redacted in report" : undefined,
      });
    }
  } catch (err) {
    result.errors.push(err instanceof Error ? err.message : String(err));
  }

  return result;
}

export async function runAllSecrets(target: string): Promise<ScanResult[]> {
  const gitleaks = await runGitleaksSecrets(target);
  const patterns = await runPatternSecrets(target);
  return [gitleaks, patterns];
}
