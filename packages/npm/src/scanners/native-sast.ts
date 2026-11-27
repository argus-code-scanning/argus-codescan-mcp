/**
 * Built-in security pattern scanner — pure Node.js, all platforms.
 * Covers common issues in JS, TS, Python, Java, PHP, Go, Ruby without external tools.
 */

import { closeSync, lstatSync, openSync, readFileSync, readSync, readdirSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import {
  IGNORE_HINT,
  type IgnoreMarker,
  downgrade,
  markerCovers,
  parseIgnore,
  pathContext,
} from "./noise.js";
import { SHARED_RULES, type SharedRuleDef } from "./shared-rules.generated.js";
import type { Confidence, Finding, ScanResult, Severity } from "./types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "__pycache__", "target", "obj", ".venv", "venv",
]);

const EXT_LANG: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
  ".py": "python", ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby", ".rs": "rust",
  ".cs": "csharp", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
  ".jsp": "jsp", ".scala": "scala", ".pl": "perl",
  ".sh": "shell", ".bash": "shell", ".zsh": "shell",
  ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
  ".bat": "batch", ".cmd": "batch",
  // Templates: only rules that list them (trackers, fingerprinting) run here.
  ".html": "html", ".htm": "html", ".vue": "vue",
  // Migrations: only rules that list sql (Supabase RLS and policies) run here.
  ".sql": "sql",
};

const SHEBANG = /^#!\s*(?:\/usr)?(?:\/local)?\/bin\/(?:env\s+(?:-\S+\s+)*)?(\w+)/;
const SHEBANG_LANG: Record<string, string> = {
  sh: "shell", bash: "shell", zsh: "shell", dash: "shell", ksh: "shell", pwsh: "powershell", powershell: "powershell",
};
const BUILD_OUTPUT = /\.(?:dll|pdb|class|exe|jar|so|o)$/i;

/** Extensionless scripts (bin/deploy, scripts/setup) by their #! line. */
function shebangLanguage(file: string): string | undefined {
  try {
    const fd = openSync(file, "r");
    const head = Buffer.alloc(200);
    const n = readSync(fd, head, 0, 200, 0);
    closeSync(fd);
    const m = SHEBANG.exec(head.subarray(0, n).toString("utf8"));
    return m ? SHEBANG_LANG[m[1]] : undefined;
  } catch {
    return undefined;
  }
}

/** bin/ holding .NET / Java build output is skipped; bin/ with scripts is scanned. */
function isBuildOutput(dir: string): boolean {
  try {
    return readdirSync(dir).some((n) => n === "Debug" || n === "Release" || BUILD_OUTPUT.test(n));
  } catch {
    return true;
  }
}

function isComment(line: string, lang: string): boolean {
  const t = line.trim();
  if (lang === "sql") return t.startsWith("--");
  if (t.startsWith("//") || t.startsWith("#")) return true;
  return lang === "batch" && (t.startsWith("::") || /^@?rem(?:\s|$)/i.test(t));
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  languages?: string[];
  multiline?: boolean;
  /** Default "medium". "low" = risky API without evidence of untrusted input. */
  confidence?: Confidence;
  /** Shown as the finding's fix advice (shared rules carry it from the YAML packs). */
  fix?: string;
  /** When this matches anywhere in the file (e.g. a __proto__ key check), confidence is low. */
  guardedBy?: RegExp;
  /** false: an argus-ignore comment can't silence it (leaked keys). Default true. */
  inlineIgnore?: boolean;
}

/** Rules generated from the argus-languages YAML packs (same ids as argus-scan). */
export function sharedRules(...packs: string[]): Rule[] {
  return SHARED_RULES.filter((r: SharedRuleDef) => packs.includes(r.pack)).map((r) => ({
    id: r.id,
    title: r.title,
    severity: r.severity,
    pattern: new RegExp(r.source, r.flags),
    languages: r.languages,
    multiline: r.multiline,
    confidence: r.confidence,
    fix: r.fixGuidance || undefined,
    guardedBy: r.guardedBy ? new RegExp(r.guardedBy, r.flags) : undefined,
    inlineIgnore: r.inlineIgnore,
  }));
}

const RULES: Rule[] = [
  {
    id: "injection-eval",
    title: "Dynamic code execution (eval/exec) — injection risk",
    severity: "high",
    // `.eval(` / `.exec(` are method calls (redis.eval of a Lua script, RegExp#exec, db.exec),
    // not eval-style execution; window/globalThis/self/global.eval( still is.
    pattern: /(?<![.\w$])eval\s*\(|\b(?:window|globalThis|self|global)\.eval\s*\(|(?<![.\w$])exec\s*\(|\bFunction\s*\(|Runtime\.getRuntime\(\)\.exec/,
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
    title: "Possible SQL injection — variable interpolated or concatenated into a SQL value",
    severity: "high",
    // Same rule as js-sql-string-build in argus-languages (#130): real SQL shape (SELECT … FROM,
    // INSERT INTO, UPDATE … SET, DELETE FROM) with a variable spliced into a value. Parameterized
    // queries ($1, ?) and log messages that merely contain "delete" are not flagged.
    pattern: /((?<![\w$])`[^`]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^`]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*[\'"(%]*\$\{|"[^"]*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^"]*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*['(%]*"\s*\+\s*[\w(]|'[^']*?(?:SELECT\b[^"\'`;]*?\bFROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\b[^"\'`;]*?\bSET|DELETE\s+FROM)\b[^']*?(?:=|<|>|\bLIKE|\bIN\s*\(|\bVALUES\s*\()\s*["(%]*'\s*\+\s*[\w(])/i,
    languages: ["javascript", "typescript"],
  },
  // ORM and query-builder escape hatches (#182), same ids and patterns as sql-injection.yaml.
  {
    id: "js-typeorm-sql-interpolation",
    title: "Possible SQL injection \u2014 variable interpolated into a TypeORM query-builder condition",
    severity: "high",
    pattern: /\.(?:where|andWhere|orWhere|having|andHaving|orHaving)\s*\(\s*(?:`[^`\n]*?(?:=|<>|<|>|\b(?:I?LIKE|i?like)\b|\b(?:IN|in)\s*\()\s*['"(%]*\$\{(?!\s*[A-Z][A-Z0-9_]*\s*\})(?!\s*[A-Za-z_$][\w$]*\(\s*(?:'[^'\n]*'|"[^"\n]*")?\s*\)\s*\})|(["'])[^"'\n]*?(?:=|<>|<|>|\b(?:I?LIKE|i?like)\b|\b(?:IN|in)\s*\()\s*['"(%]*\1\s*\+\s*(?![A-Z][A-Z0-9_]*\b)[\w$(])/,
    languages: ["javascript", "typescript"],
  },
  {
    id: "js-knex-raw-interpolation",
    title: "Possible SQL injection \u2014 variable passed into a Knex raw SQL method",
    severity: "high",
    pattern: /(?:\.(?:whereRaw|orWhereRaw|andWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw|fromRaw)|\b(?:knex|trx|db)\.raw)\s*\(\s*(?:`[^`\n]*\$\{(?!\s*[A-Z][A-Z0-9_]*\s*\})(?!\s*[A-Za-z_$][\w$]*\(\s*(?:'[^'\n]*'|"[^"\n]*")?\s*\)\s*\})|["'][^"'\n]*["']\s*\+\s*(?![A-Z][A-Z0-9_]*\b)[\w$(]|(?![A-Z][A-Z0-9_]*\b)[A-Za-z_$][\w$.]*\s*[,)])/,
    languages: ["javascript", "typescript"],
  },
  {
    id: "js-prisma-raw-unsafe",
    title: "Possible SQL injection \u2014 Prisma $queryRawUnsafe / $executeRawUnsafe or Prisma.raw with a built string",
    severity: "high",
    pattern: /\$(?:query|execute)RawUnsafe\s*\(\s*(?:`[^`\n]*\$\{(?!\s*[A-Z][A-Z0-9_]*\s*\})(?!\s*[A-Za-z_$][\w$]*\(\s*(?:'[^'\n]*'|"[^"\n]*")?\s*\)\s*\})|["'][^"'\n]*["']\s*\+\s*(?![A-Z][A-Z0-9_]*\b)[\w$(]|(?![A-Z][A-Z0-9_]*\b)[A-Za-z_$][\w$.]*\s*[,)])|\bPrisma\.raw\s*\(\s*(?!["'`])(?![A-Z][A-Z0-9_]*\b)[A-Za-z_$]/,
    languages: ["javascript", "typescript"],
  },
  {
    id: "js-sequelize-literal-interpolation",
    title: "Possible SQL injection \u2014 variable passed into sequelize.literal()",
    severity: "high",
    pattern: /\b[Ss]equelize\.literal\s*\(\s*(?:`[^`\n]*\$\{(?!\s*[A-Z][A-Z0-9_]*\s*\})(?!\s*[A-Za-z_$][\w$]*\(\s*(?:'[^'\n]*'|"[^"\n]*")?\s*\)\s*\})|["'][^"'\n]*["']\s*\+\s*(?![A-Z][A-Z0-9_]*\b)[\w$(]|(?![A-Z][A-Z0-9_]*\b)[A-Za-z_$][\w$.]*\s*[,)])/,
    languages: ["javascript", "typescript"],
  },
  {
    id: "js-orm-order-by-input",
    title: "ORDER BY / GROUP BY built from request input \u2014 check it is limited to an allow-list",
    severity: "moderate",
    confidence: "low",
    pattern: /\.(?:orderBy|addOrderBy|groupBy|addGroupBy)\s*\(\s*(?:`[^`\n]*\$\{\s*(?:req|request|query|body|params|dto|filter|filters|input|args|options|opts|sort\w*)\b|(?:req|request)\.(?:query|body|params)\b)/,
    languages: ["javascript", "typescript"],
  },
  // Shell, PowerShell and batch scripts (#219, #220): same ids and patterns as shell.yaml,
  // powershell.yaml and batch.yaml in argus-languages.
  {
    id: "sh-eval-variable",
    title: "eval runs a variable or argument as shell code",
    severity: "high",
    pattern: /(?:^|[;&|({]\s*|\bthen\s+|\bdo\s+)eval\s+["']?\$(?!\()(?:\{?[A-Za-z_@*0-9])/,
    languages: ["shell"],
  },
  {
    id: "sh-rm-unguarded-variable",
    title: "rm -rf on a variable path with no empty-value guard (an empty variable deletes from /)",
    severity: "high",
    // One options group + lookahead for an -r style option: linear (the old split was quadratic, #265).
    pattern: /\brm\s+(?=(?:-[a-zA-Z-]+\s+)*?-[a-zA-Z]*[rR][a-zA-Z]*\s)(?:-[a-zA-Z-]+\s+)+"?\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)"?\/(?:\*|["'\s;]|$)/,
    languages: ["shell"],
  },
  {
    id: "sh-tls-verification-off",
    title: "TLS certificate verification turned off",
    severity: "high",
    pattern: /\bcurl\b[^\n#]*\s(?:--insecure\b|-[a-zA-Z]*k[a-zA-Z]*(?=\s|$))|\bwget\b[^\n#]*--no-check-certificate|\bgit\b[^\n#]*http\.sslVerify[= ]+false|\bGIT_SSL_NO_VERIFY=["']?(?:1|true)|\bnpm\s+config\s+set\s+strict-ssl\s+false|\bNODE_TLS_REJECT_UNAUTHORIZED=["']?0|\bpip3?\s+install\b[^\n#]*--trusted-host/,
    languages: ["shell"],
  },
  {
    id: "sh-chmod-world-writable",
    title: "chmod makes files world-writable (777 / 666 / o+w)",
    severity: "moderate",
    pattern: /\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:0?[0-7]?(?:777|666)|[ugoa]*[oa][ugoa]*\+[rxX]*w)\b/,
    languages: ["shell"],
  },
  {
    id: "sh-password-on-command-line",
    title: "Password or secret written into the script or passed on the command line",
    severity: "high",
    confidence: "medium",
    pattern: /\bsshpass\s+-p\s*["']?[^\s"'$-]|\bmysql(?:dump|admin)?\b[^\n#]*\s(?:-p|--password=)["']?[^\s"'$-][^\s"']*|\b(?:PGPASSWORD|MYSQL_PWD)=["']?[^\s"'$]{3,}|\bexport\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)\w*=["']?[A-Za-z0-9\/+_.@!-]{6,}["']?\s*(?:$|#|;)/,
    languages: ["shell"],
  },
  {
    id: "sh-predictable-tmp-file",
    title: "Script writes to a fixed /tmp path (symlink or race attacks)",
    severity: "moderate",
    confidence: "low",
    pattern: /(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?\/tmp\/(?:[\w.-]+|\$\$)(?:["'\s;]|$)/,
    languages: ["shell"],
  },
  {
    id: "sh-sudoers-nopasswd",
    title: "Script grants passwordless sudo or edits sudoers directly",
    severity: "high",
    pattern: /NOPASSWD:\s*ALL\b|(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?\/etc\/sudoers(?:\.d\/[\w.-]+)?\b/,
    languages: ["shell"],
  },
  {
    id: "sh-ssh-host-key-check-off",
    title: "SSH host key checking turned off (man-in-the-middle)",
    severity: "moderate",
    pattern: /StrictHostKeyChecking[= ]+["']?no\b|UserKnownHostsFile[= ]+["']?\/dev\/null/,
    languages: ["shell"],
  },
  {
    id: "ps-invoke-expression-variable",
    title: "Invoke-Expression runs a variable as PowerShell code",
    severity: "high",
    pattern: /\b(?:Invoke-Expression|iex)\s+(?:-Command\s+)?\$\w|\$\w+\s*\|\s*(?:Invoke-Expression|iex)\b/i,
    languages: ["powershell"],
  },
  {
    id: "ps-execution-policy-bypass",
    title: "Execution policy set to Bypass / Unrestricted",
    severity: "moderate",
    pattern: /-(?:ExecutionPolicy|ep|exec)\s+["']?(?:Bypass|Unrestricted)\b|\bSet-ExecutionPolicy\s+(?:-ExecutionPolicy\s+)?["']?(?:Bypass|Unrestricted)\b/i,
    languages: ["powershell",  "batch"],
  },
  {
    id: "ps-plaintext-password",
    title: "Plaintext password turned into a SecureString (ConvertTo-SecureString -AsPlainText)",
    severity: "high",
    confidence: "medium",
    pattern: /\bConvertTo-SecureString\s+(?:-String\s+)?["'][^"'$]+["']\s+-AsPlainText/i,
    languages: ["powershell"],
  },
  {
    id: "ps-tls-validation-off",
    title: "TLS certificate validation turned off",
    severity: "high",
    pattern: /ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}|-SkipCertificateCheck\b|\bTrustAllCertsPolicy\b|CheckValidationResult\s*\([^)]*\)\s*\{\s*return\s+true/i,
    languages: ["powershell"],
  },
  {
    id: "ps-weak-tls-protocol",
    title: "Script enables SSL 3 / TLS 1.0 / TLS 1.1",
    severity: "moderate",
    pattern: /SecurityProtocolType\]::(?:Ssl3|Tls11|Tls)(?!\w)/i,
    languages: ["powershell"],
  },
  {
    id: "bat-add-admin-user",
    title: "Script creates a local user or adds one to Administrators",
    severity: "high",
    pattern: /\bnet\s+user\s+\S+\s+\S+\s+\/add\b|\bnet\s+localgroup\s+administrators\s+\S+\s+\/add\b/i,
    languages: ["batch",  "powershell"],
  },
  {
    id: "bat-plaintext-credentials",
    title: "Plaintext password in a batch script",
    severity: "high",
    confidence: "medium",
    pattern: /\bnet\s+use\b[^\n]*\/user:\S+\s+(?!\*)(?!%)[^\s\/]+|\brunas\b[^\n]*\/savecred\b|^\s*set\s+"?\w*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN)\w*=[^%\s"]{4,}/i,
    languages: ["batch"],
  },
  {
    id: "bat-firewall-disabled",
    title: "Script turns the Windows firewall off",
    severity: "high",
    pattern: /\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b|\bnetsh\s+firewall\s+set\s+opmode\s+(?:mode=)?disable\b|Set-NetFirewallProfile\b[^\n]*-Enabled\s+(?:False|\$false|0)/i,
    languages: ["batch",  "powershell"],
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
    // shadcn/ui chart.tsx (in most Lovable / v0 apps) writes CSS built from its own THEMES constant.
    guardedBy: /__html:\s*Object\.entries\(THEMES\)/,
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
  // ── Server-side template injection (#185), ported from argus-languages ssti.yaml ──
  {
    id: "python-ssti-render-template-string",
    title: "Template injection \u2014 render_template_string() with a non-literal template (Flask / Jinja2)",
    severity: "high",
    pattern: /\brender_template_string\s*\(\s*(?:(?![rRuU]?(?:"""|'''|"|'))|[rRuU]?(?:"|')[^"'\n]*(?:"|')\s*(?:\+|%|\.format\b))/,
    languages: ["python"],
  },
  {
    id: "python-ssti-template-from-input",
    title: "Template injection \u2014 Jinja2 / Django / Mako template built from request input or an f-string",
    severity: "high",
    pattern: /(?<!string\.)\b(?:jinja2\.)?Template\s*\(\s*(?:request\.|[rR]?f["'])|\bjinja2\.Template\s*\(\s*(?![rRuU]?["'])|\b(?:\w*env(?:ironment)?|jinja\w*|engines\[[^\]\n]+\])\.from_string\s*\(\s*(?![rRuU]?(?:"""|'''|"|'))/,
    languages: ["python"],
  },
  {
    id: "js-ssti-render-user-template",
    title: "Template injection \u2014 template engine compiles a template built from request input (EJS, Pug, Handlebars, Nunjucks, lodash)",
    severity: "high",
    pattern: /\b(?:ejs|pug|jade|nunjucks|handlebars|Handlebars|mustache|Mustache|doT|dot|hogan|Hogan|swig|_|lodash)\.(?:render|renderString|compile|compileTemplate|template)\s*\(\s*(?:[^,)\n]*\breq(?:uest)?\.(?:body|query|params|headers|cookies)\b|`[^`\n]*\$\{|["'][^"'\n]*["']\s*\+)/,
    languages: ["javascript", "typescript"],
  },
  {
    id: "php-ssti-template-from-input",
    title: "Template injection \u2014 Twig / Blade / Smarty template created from request input",
    severity: "high",
    pattern: /->createTemplate\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->)|Blade::render\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\b|\$request->|request\(\))|->fetch\s*\(\s*["']string:["']\s*\.\s*\$|->fetch\s*\(\s*["']string:[^"']*\$/,
    languages: ["php"],
  },
  {
    id: "java-ssti-freemarker-string-template",
    title: "Template injection \u2014 FreeMarker Template built from a non-literal string",
    severity: "high",
    pattern: /new\s+(?:freemarker\.template\.)?Template\s*\([^,\n]+,\s*new\s+StringReader\s*\(\s*(?!")/,
    languages: ["java", "kotlin"],
  },
  {
    id: "java-ssti-velocity-evaluate",
    title: "Template injection \u2014 Velocity evaluate() of a template string \u2014 review: is the template user-controlled?",
    severity: "moderate",
    pattern: /\b(?:Velocity|velocityEngine|velocity|ve)\.evaluate\s*\(/,
    languages: ["java", "kotlin"],
    confidence: "low",
  },
  {
    id: "ruby-ssti-erb-from-input",
    title: "Template injection \u2014 ERB template built from request input",
    severity: "high",
    pattern: /\bERB\.new\s*\(\s*(?:params|request|cookies)\b|\bERB\.new\s*\(\s*"[^"\n]*#\{(?:params|request)/,
    languages: ["ruby"],
  },
];

/** Spring Boot externalised config: application.properties, application-prod.yml, ... */
function isSpringConfig(name: string): boolean {
  return /^(?:application|bootstrap)(?:-[\w.-]+)?\.(?:properties|ya?ml)$/.test(name);
}

/** Language for a file name, or undefined when argus-native doesn't scan it. */
function languageOf(name: string, full?: string): string | undefined {
  if (isSpringConfig(name)) return "spring-config";
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".")).toLowerCase() : "";
  if (!ext && full) return shebangLanguage(full);
  return EXT_LANG[ext];
}

// Config files and templates only get rules written for them; generic code rules would misfire
// on KEY=value or on HTML.
const CONFIG_LANGUAGES = new Set(["spring-config", "html", "vue", "sql"]);

// Same default set as argus-scan: its cookie and PII-in-logs packs run in every code scan.
// The Java, Rust and Go packs are generated from argus-languages. Where npm still has an older
// copy of a rule with the same id (java-xxe, spring-csrf-disabled…), the shared version wins.
const SHARED_DEFAULT_RULES = sharedRules(
  "cookies", "pii", "prototype-pollution", "header-injection", "vibe", "java", "rust", "go",
);
const SHARED_IDS = new Set(SHARED_DEFAULT_RULES.map((r) => r.id));
const DEFAULT_RULES: Rule[] = [...RULES.filter((r) => !SHARED_IDS.has(r.id)), ...SHARED_DEFAULT_RULES];

function walkFiles(dir: string, out: string[], depth = 0): void {
  if (depth > 14) return;
  try {
    const root = lstatSync(dir);
    if (root.isSymbolicLink()) return;
    if (!root.isDirectory()) {
      if (languageOf(basename(dir), dir)) out.push(dir);
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
    if (name === "bin" && isBuildOutput(full)) continue;
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
      if (languageOf(name, full)) out.push(full);
    }
  }
}

export async function runNativeSast(
  target: string,
  options: { rules?: Rule[]; tool?: string } = {},
): Promise<ScanResult> {
  const rules = options.rules ?? DEFAULT_RULES;
  const tool = options.tool ?? "argus-native";
  const result: ScanResult = {
    tool,
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
    const lang = languageOf(basename(file), file) ?? "unknown";
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    const scanSource = lines.map((line) => (isComment(line, lang) ? "" : line)).join("\n");
    const rel = relative(lstatSync(target).isDirectory() ? target : dirname(target), file);
    const context = pathContext(rel);
    let pending: IgnoreMarker | undefined; // from a comment-only line just above

    const markers: Array<IgnoreMarker | undefined> = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (isComment(trimmed, lang)) {
        pending = parseIgnore(line);
        markers.push(undefined);
        continue;
      }
      markers.push(parseIgnore(line) ?? pending);
      pending = undefined;
    }

    for (const rule of rules) {
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
          if (isComment(line, lang)) continue;
          if (rule.pattern.test(line)) matchedLines.add(i + 1);
        }
      }

      for (const lineNumber of [...matchedLines].sort((a, b) => a - b)) {
        const marker = markers[lineNumber - 1];
        let description = `Language: ${lang}`;
        if (marker && rule.inlineIgnore !== false && markerCovers(marker, rule.id)) {
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
          tool,
          file: rel,
          line: lineNumber,
          ruleId: rule.id,
          description,
          confidence: rule.confidence ?? "medium",
        };
        if (rule.guardedBy?.test(content)) {
          finding.confidence = "low";
          finding.description += " (the file has a guard for this; check it covers this line)";
        }
        if (rule.fix) finding.fix = rule.fix;
        if (context) finding.context = context;
        result.findings.push(finding);
      }
    }
  }

  return result;
}
