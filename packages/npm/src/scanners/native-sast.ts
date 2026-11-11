/**
 * Built-in security pattern scanner — pure Node.js, all platforms.
 * Covers common issues in JS, TS, Python, Java, PHP, Go, Ruby without external tools.
 */

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import {
  IGNORE_HINT,
  type IgnoreMarker,
  downgrade,
  markerCovers,
  parseIgnore,
  pathContext,
} from "./noise.js";
import type { Confidence, Finding, ScanResult, Severity } from "./types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "__pycache__", "target", "bin", "obj", ".venv", "venv",
]);

const EXT_LANG: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby",
  ".cs": "csharp", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
  ".jsp": "jsp", ".scala": "scala", ".pl": "perl",
  ".sh": "shell", ".bash": "shell", ".zsh": "shell",
};

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  languages?: string[];
  multiline?: boolean;
  /** Default "medium". "low" = risky API without evidence of untrusted input. */
  confidence?: Confidence;
}

const RULES: Rule[] = [
  {
    id: "injection-eval",
    title: "Dynamic code execution (eval/exec) — injection risk",
    severity: "high",
    // `.exec(` is a method call (RegExp#exec, db.exec), not eval-style execution.
    pattern: /\beval\s*\(|(?<![.\w])exec\s*\(|\bFunction\s*\(|Runtime\.getRuntime\(\)\.exec/,
  },
  {
    id: "sql-concat",
    title: "Possible SQL injection — string concatenation in query",
    severity: "high",
    pattern: /(Statement\.execute\s*\(|createStatement\s*\(\).*\+|mysql_query\s*\(|mysqli_query\s*\(|f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b|["'].*\+\s*["'].*\bWHERE\b)/i,
    languages: ["php", "python", "ruby"],
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
    title: "Possible command injection — dynamic shell execution",
    severity: "high",
    pattern: /\bos\.(?:system|popen)\s*\(\s*(?:[A-Za-z_$][\w$]*(?:\s*\([^)]{0,120}\))?|["'][^"']{0,160}["']\s*(?:\+|%|\.format\s*\()|f["'][^"']*\{)|\bsubprocess\.(?:call|Popen|run)\s*\((?:[\s\S]{0,300}?\bshell\s*=\s*True\b|f["']|["'][^"']{0,160}["']\s*(?:\+|%|\.format\s*\())/,
    multiline: true,
    languages: ["python"],
  },
  {
    id: "command-injection",
    title: "Possible command injection — dynamic shell execution",
    severity: "high",
    pattern: /(?:(?:\b(?:child_process|childProcess|cp)\.)|(?<![\w$.]))exec(?:Sync)?\s*\(\s*(?:[A-Za-z_$][\w$]*(?:\s*\([^)]{0,120}\))?|["'][^"']{0,160}["']\s*(?:\+|\.format\s*\()|`[^`]{0,160}\$\{)/,
    multiline: true,
    languages: ["javascript", "typescript"],
  },
  {
    id: "command-injection",
    title: "Possible command injection — dynamic shell execution",
    severity: "high",
    pattern: /(?:Runtime\.getRuntime\(\)\.exec\s*\(\s*(?!new\s+String\s*\[\s*\])(?:[A-Za-z_$][\w$]*(?:\s*\([^)]{0,120}\))?|["'][^"']{0,160}["']\s*\+)|new\s+ProcessBuilder\s*\(\s*["'](?:sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*["'](?:-c|\/c|--command)["']\s*,\s*(?:[A-Za-z_$][\w$]*|["'][^"']{0,160}["']\s*\+))/,
    multiline: true,
    languages: ["java", "kotlin"],
  },
  {
    id: "command-injection",
    title: "Possible command injection — dynamic shell execution",
    severity: "high",
    pattern: /exec\.Command\s*\(\s*["'](?:sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*["'](?:-c|\/c|--command)["']\s*,\s*(?:[A-Za-z_$][\w$]*|["'][^"']{0,160}["']\s*\+)/,
    multiline: true,
    languages: ["go"],
  },
  {
    id: "command-injection",
    title: "Possible command injection — dynamic shell execution",
    severity: "high",
    pattern: /(?:Process\.Start\s*\(\s*["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?)["']\s*,\s*(?:["'][^"']{0,160}["']\s*\+|[A-Za-z_$][\w$]*)|\bsystem\s*\(\s*(?:[A-Za-z_$][\w$]*|["'][^"']{0,160}(?:#\{|\$[A-Za-z_])|["'][^"']{0,160}["']\s*\+)|\bsystem\s+\$[A-Za-z_][\w$]*|`[^`]{0,200}(?:#\{|\$[A-Za-z_])|%x.{0,200}(?:#\{|\$[A-Za-z_])|\b(?:sh|bash|zsh)\s+-c\s+["'][^"']{0,160}\$[A-Za-z_])/,
    multiline: true,
    languages: ["csharp", "ruby", "perl", "shell"],
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
  // ── Java / Kotlin / Spring, ported from argus-languages (same ids and patterns) ──
  {
    id: "java-sql-string-build",
    title: "Possible SQL injection \u2014 variable concatenated or formatted into a SQL value",
    severity: "high",
    pattern: /("[^"]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^"]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*['(%]*"\s*\+\s*[\w(]|"[^"]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^"]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*['(%]*%[sd][^"]*"\s*\.formatted\(|\bString\.format\(\s*"[^"]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^"]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*['(%]*%[sd])/i,
    languages: ["java", "kotlin"],
  },
  {
    id: "kotlin-sql-string-template",
    title: "Possible SQL injection \u2014 variable interpolated into a SQL value with a string template",
    severity: "high",
    pattern: /"[^"]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^"]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*['(%]*\$\{?[A-Za-z_]/i,
    languages: ["kotlin"],
  },
  {
    id: "java-sql-statement-concat",
    title: "Java SQL Statement built via string concatenation",
    severity: "high",
    pattern: /(Statement\.execute\s*\(|createStatement\s*\(\).*\+|PreparedStatement.*\+.*\+)/,
    languages: ["java", "kotlin", "scala"],
  },
  {
    id: "db-jdbc-statement-concat",
    title: "JDBC Statement built with string concatenation",
    severity: "high",
    pattern: /(createStatement|prepareStatement)\s*\([^)]*\+/,
    languages: ["java", "kotlin", "scala"],
  },
  {
    id: "db-sql-dynamic-exec",
    title: "Dynamic SQL EXEC/EXECUTE \u2014 injection risk",
    severity: "high",
    pattern: /(EXEC\s*\(|EXECUTE\s+IMMEDIATE\s+|sp_executesql\s*\()/i,
    languages: ["java"],
  },
  {
    id: "java-xxe",
    title: "Possible XXE \u2014 XML parser without secure features",
    severity: "high",
    pattern: /(DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance)/,
    languages: ["java", "kotlin", "scala"],
  },
  {
    id: "java-ldap-injection",
    title: "Possible LDAP injection \u2014 concatenated filter",
    severity: "high",
    pattern: /(search\s*\([^)]*\+|DirContext\.search\s*\([^)]*\+)/,
    languages: ["java", "kotlin"],
  },
  {
    id: "java-path-traversal",
    title: "Possible path traversal \u2014 user input in file path",
    severity: "moderate",
    pattern: /(Paths\.get\s*\([^)]*\+|Files\.(read|write).*\+)/,
    languages: ["java", "kotlin", "scala"],
  },
  {
    id: "java-log-injection",
    title: "Possible log injection \u2014 user input in log statement",
    severity: "low",
    pattern: /(logger\.(info|warn|error|debug)\s*\([^)]*\+.*request\.|log\.(info|warn|error)\s*\([^)]*\+)/,
    languages: ["java", "kotlin"],
    confidence: "low",
  },
  {
    id: "java-jjwt-unsigned-parse",
    title: "jjwt parses an unsigned token \u2014 anyone can forge it",
    severity: "high",
    pattern: /\.(parseClaimsJwt|parsePlaintextJwt|parseUnsecuredClaims|parseUnsecuredContent)\s*\(/,
    languages: ["java"],
  },
  {
    id: "java-spring-permitall-everything",
    title: "Spring Security permits every request without authentication (permitAll on anyRequest or \"/**\")",
    severity: "high",
    pattern: /(\.anyRequest\(\)\s*\.permitAll\(\)|\.(requestMatchers|antMatchers|mvcMatchers)\(\s*"\/\*\*"\s*\)\s*\.permitAll\(\)|\bauthorize\(\s*anyRequest\s*,\s*permitAll\s*\))/,
    languages: ["java", "kotlin"],
  },
  {
    id: "java-spring-web-ignoring-everything",
    title: "Spring Security ignores every request (web.ignoring on anyRequest or \"/**\") \u2014 no filters run at all",
    severity: "high",
    pattern: /\.ignoring\(\)\s*\.(anyRequest\(\)|(requestMatchers|antMatchers|mvcMatchers)\(\s*"\/\*\*"\s*\))/,
    languages: ["java", "kotlin"],
  },
  {
    id: "java-jsr250-permitall",
    title: "@PermitAll opens this controller or method to everyone \u2014 review: is it meant to be public?",
    severity: "moderate",
    pattern: /^(?!\s*(import\b|\/\/|\*)).*@PermitAll\b/,
    languages: ["java", "kotlin"],
    confidence: "low",
  },
  {
    id: "spring-csrf-disabled",
    title: "Spring CSRF protection disabled",
    severity: "moderate",
    pattern: /\.csrf\s*\(\s*\)\.disable\s*\(\)/,
    languages: ["java", "kotlin"],
  },
  {
    id: "malware-jsp-webshell",
    title: "JSP / Java runtime exec web shell pattern",
    severity: "critical",
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(/i,
    languages: ["jsp"],
  },
  {
    id: "spring-actuator-exposure-all",
    title: "Spring Boot Actuator exposes every endpoint over HTTP (exposure.include = *) \u2014 /env, /heapdump and /threaddump included",
    severity: "high",
    pattern: /^\s*(management\.endpoints\.web\.exposure\.include\s*[=:]\s*['"]?\*|include\s*:\s*['"]\*['"]\s*(#.*)?$)/,
    languages: ["spring-config"],
  },
  {
    id: "spring-h2-console-enabled",
    title: "H2 web console is enabled (spring.h2.console.enabled) \u2014 make sure this is a dev-only profile",
    severity: "moderate",
    pattern: /^\s*spring\.h2\.console\.enabled\s*[=:]\s*['"]?true\b/,
    languages: ["spring-config"],
  },
];

/** Spring Boot externalised config: application.properties, application-prod.yml, ... */
function isSpringConfig(name: string): boolean {
  return /^(?:application|bootstrap)(?:-[\w.-]+)?\.(?:properties|ya?ml)$/.test(name);
}

/** Language for a file name, or undefined when argus-native doesn't scan it. */
function languageOf(name: string): string | undefined {
  if (isSpringConfig(name)) return "spring-config";
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".")).toLowerCase() : "";
  return EXT_LANG[ext];
}

// Config files only get rules written for them; generic code rules would misfire on KEY=value.
const CONFIG_LANGUAGES = new Set(["spring-config"]);

function walkFiles(dir: string, out: string[], depth = 0): void {
  if (depth > 14) return;
  try {
    const root = lstatSync(dir);
    if (root.isSymbolicLink()) return;
    if (!root.isDirectory()) {
      if (languageOf(basename(dir))) out.push(dir);
      return;
    }
  } catch {
    return;
  }
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
      st = lstatSync(full);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      walkFiles(full, out, depth + 1);
    } else {
      if (languageOf(name)) out.push(full);
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
    const lang = languageOf(basename(file)) ?? "unknown";
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    const scanSource = lines.map((line) =>
      line.trim().startsWith("//") || line.trim().startsWith("#") ? "" : line,
    ).join("\n");
    const rel = relative(lstatSync(target).isDirectory() ? target : dirname(target), file);
    const context = pathContext(rel);
    let pending: IgnoreMarker | undefined; // from a comment-only line just above

    const markers: Array<IgnoreMarker | undefined> = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
        pending = parseIgnore(line);
        markers.push(undefined);
        continue;
      }
      markers.push(parseIgnore(line) ?? pending);
      pending = undefined;
    }

    for (const rule of RULES) {
      if (rule.languages ? !rule.languages.includes(lang) : CONFIG_LANGUAGES.has(lang)) continue;

      const matchedLines = new Set<number>();
      if (rule.multiline) {
        const globalPattern = new RegExp(rule.pattern.source, `${rule.pattern.flags}g`);
        let sourceOffset = 0;
        let lineNumber = 1;
        for (const match of scanSource.matchAll(globalPattern)) {
          const index = match.index ?? 0;
          while (sourceOffset < index) {
            if (scanSource[sourceOffset] === "\n") lineNumber++;
            sourceOffset++;
          }
          matchedLines.add(lineNumber);
        }
      } else {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trim().startsWith("//") || line.trim().startsWith("#")) continue;
          if (rule.pattern.test(line)) matchedLines.add(i + 1);
        }
      }

      for (const lineNumber of [...matchedLines].sort((a, b) => a - b)) {
        const marker = markers[lineNumber - 1];
        let description = `Language: ${lang}`;
        if (marker && markerCovers(marker, rule.id)) {
          if (marker.reason) {
            (result.suppressed ??= []).push({
              ruleId: rule.id,
              file: rel,
              line: lineNumber,
              reason: marker.reason,
            });
            continue;
          }
          description += IGNORE_HINT(rule.id);
        }
        const finding: Finding = {
          title: rule.title,
          severity: context ? downgrade(rule.severity) : rule.severity,
          tool: "argus-native",
          file: rel,
          line: lineNumber,
          ruleId: rule.id,
          description,
          confidence: rule.confidence ?? "medium",
        };
        if (context) finding.context = context;
        result.findings.push(finding);
      }
    }
  }

  return result;
}
