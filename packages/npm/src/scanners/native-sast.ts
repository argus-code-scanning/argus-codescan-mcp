/**
 * Built-in security pattern scanner — pure Node.js, all platforms.
 * Covers common issues in JS, TS, Python, Java, PHP, Go, Ruby without external tools.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding, ScanResult, Severity } from "./types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "__pycache__", "target", "bin", "obj", ".venv", "venv",
]);

const EXT_LANG: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby",
  ".cs": "csharp", ".kt": "kotlin", ".swift": "swift",
};

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  languages?: string[];
}

const RULES: Rule[] = [
  {
    id: "injection-eval",
    title: "Dynamic code execution (eval/exec) — injection risk",
    severity: "high",
    pattern: /\beval\s*\(|\bexec\s*\(|\bFunction\s*\(|Runtime\.getRuntime\(\)\.exec/,
  },
  {
    id: "sql-concat",
    title: "Possible SQL injection — string concatenation in query",
    severity: "high",
    pattern: /(Statement\.execute\s*\(|createStatement\s*\(\).*\+|mysql_query\s*\(|mysqli_query\s*\(|f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b|["'].*\+\s*["'].*\bWHERE\b)/i,
    languages: ["java", "php", "python", "ruby"],
  },
  {
    id: "sql-concat-js",
    title: "Possible SQL injection — dynamic SQL in query call",
    severity: "high",
    pattern: /\.(query|execute|raw|rawQuery|sql)\s*\(\s*[`'"].*\b(SELECT|INSERT|UPDATE|DELETE)\b|`[^`]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{|['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+/i,
    languages: ["javascript", "typescript"],
  },
  {
    id: "command-injection",
    title: "Possible command injection — shell execution with user input",
    severity: "high",
    pattern: /(os\.system|subprocess\.(call|Popen|run)|shell_exec|exec\s*\(|passthru|system\s*\(|ProcessBuilder|child_process\.exec)/,
  },
  {
    id: "xss-innerhtml",
    title: "Possible XSS — unsafe HTML insertion",
    severity: "high",
    pattern: /(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=)/,
    languages: ["javascript", "typescript", "php"],
  },
  {
    id: "path-traversal",
    title: "Possible path traversal — user input in file path",
    severity: "moderate",
    pattern: /(open\s*\([^)]*\+|readFile\s*\([^)]*\+|include\s*\(\s*\$|require\s*\(\s*\$)/,
  },
  {
    id: "weak-crypto",
    title: "Weak cryptography (MD5/SHA1/DES/ECB)",
    severity: "moderate",
    pattern: /\b(MD5|SHA-?1|ECB)\b|createHash\s*\(\s*["']md5|MessageDigest\.getInstance\s*\(\s*["']MD5|(?<![a-zA-Z])DES(?![a-zA-Z])/i,
  },
  {
    id: "hardcoded-password",
    title: "Hardcoded password or secret assignment",
    severity: "high",
    pattern: /(password\s*=\s*["'][^"']{4,}["']|passwd\s*=\s*["']|api_key\s*=\s*["'][^"']+["'])/i,
  },
  {
    id: "debug-enabled",
    title: "Debug mode enabled in production code",
    severity: "low",
    pattern: /(DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|development\s*:\s*true)/i,
  },
  {
    id: "cors-wildcard",
    title: "CORS allows all origins (*)",
    severity: "moderate",
    pattern: /(Access-Control-Allow-Origin['"]\s*,\s*['"]\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*)/,
  },
  {
    id: "nosql-injection",
    title: "Possible NoSQL injection — $where or raw query object",
    severity: "high",
    pattern: /(\$where|\$regex.*\+|find\s*\(\s*\{[^}]*\$)/,
    languages: ["javascript", "typescript", "python"],
  },
  {
    id: "deserialization",
    title: "Unsafe deserialization",
    severity: "high",
    pattern: /(pickle\.loads|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream|readObject\s*\()/,
  },
  {
    id: "ssrf-fetch",
    title: "Possible SSRF — URL fetch may use user-controlled input",
    severity: "moderate",
    pattern: /(fetch\s*\([^)]*\+|requests\.(get|post)\s*\([^)]*\+|HttpClient.*\+|file_get_contents\s*\(\s*\$)/,
  },
];

function walkFiles(dir: string, out: string[], depth = 0): void {
  if (depth > 14) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name) || name.startsWith(".")) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walkFiles(full, out, depth + 1);
    } else {
      const ext = name.includes(".") ? name.slice(name.lastIndexOf(".")) : "";
      if (EXT_LANG[ext]) out.push(full);
    }
  }
}

export async function runNativeSast(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    tool: "argus-native",
    scanType: "sast",
    target,
    findings: [],
    errors: [],
  };

  const files: string[] = [];
  walkFiles(target, files);

  if (files.length === 0) {
    result.errors.push("No source files found to scan");
    return result;
  }

  for (const file of files) {
    const ext = file.slice(file.lastIndexOf("."));
    const lang = EXT_LANG[ext] ?? "unknown";
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    const rel = relative(target, file);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith("//") || line.trim().startsWith("#")) continue;

      for (const rule of RULES) {
        if (rule.languages && !rule.languages.includes(lang)) continue;
        if (rule.pattern.test(line)) {
          result.findings.push({
            title: rule.title,
            severity: rule.severity,
            tool: "argus-native",
            file: rel,
            line: i + 1,
            ruleId: rule.id,
            description: `Language: ${lang}`,
          });
        }
      }
    }
  }

  return result;
}
