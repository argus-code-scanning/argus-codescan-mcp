/**
 * `argus-codescan scan vibe` (#273): a launch check for apps built with AI tools.
 *
 * Same checks, rule ids, score and prompts as argus-scan's `argus scan vibe`
 * (argus/tools/vibe_checks.py + argus/vibe_report.py). Files are read, never run, and
 * secret values never appear in the output or in the fix prompts.
 */

import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { runNativeSast } from "./native-sast.js";
import { pathContext } from "./noise.js";
import { runPiiScan } from "./privacy.js";
import { runPatternSecrets } from "./secrets.js";
import { SHARED_RULES } from "./shared-rules.generated.js";
import type { Confidence, Finding, ScanResult, Severity } from "./types.js";

const TOOL = "argus-vibe";
const SKIP_DIRS = new Set([
  ".git", "node_modules", ".next", "dist", "build", "out", ".vercel", ".turbo", "coverage",
  ".venv", "venv", "__pycache__", ".svelte-kit", ".nuxt", ".expo", "vendor",
]);
const MAX_FILE = 1024 * 1024;
const CODE_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py"]);
const BROWSER_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"]);

// --- patterns (kept in step with vibe_checks.py) ---------------------------------------------

const CREATE_TABLE = /\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?/gi;
const ENABLE_RLS =
  /\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/gi;
const ENABLE_RLS_LOOP =
  /\b(?:pg_tables|information_schema\.tables)\b[\s\S]{0,400}?format\(\s*'[^']*enable\s+row\s+level\s+security/gi;
const FIRESTORE_OPEN =
  /\ballow\s+(?:read|write|get|list|create|update|delete)(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*(?::\s*if\s+true\s*)?;/gi;
const FIRESTORE_TEST_MODE = /request\.time\s*<\s*timestamp\.date\(/g;
const RTDB_OPEN = /"\.(?:read|write)"\s*:\s*(?:true|"true")/g;
const SERVICE_ROLE_REF = /service_?role/i;
const USE_CLIENT = /^\s*['"]use client['"]/m;
const USE_SERVER = /^\s*['"]use server['"]/m;
const ROUTE_MUTATION =
  /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/;
const SERVER_ACTION = /export\s+(?:default\s+)?async\s+function\s+(\w*)/;
const DATA_CHANGE = new RegExp(
  [
    String.raw`\.(?:insert|upsert|update|delete|remove)\s*\(`,
    String.raw`\bprisma\.\w+\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(`,
    String.raw`\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b`,
    String.raw`\b(?:setDoc|addDoc|updateDoc|deleteDoc)\s*\(|\.save\s*\(`,
  ].join("|"),
  "i",
);
const AUTH_EVIDENCE = new RegExp(
  [
    String.raw`\bauth\(\)|getServerSession|currentUser\s*\(|\bgetUser\s*\(|getSession\s*\(|getAuth\s*\(`,
    String.raw`clerkClient|requireAuth|requireUser|withAuth|verifyToken|jwt\.verify|jwtVerify|getToken\s*\(`,
    String.raw`validateRequest|isAuthenticated|session\??\.user|auth\.getUser|authenticate\s*\(|checkAuth`,
    String.raw`ensureAuth|protectedProcedure|constructEvent|verifySignature|verifyWebhook|unauthorized`,
    String.raw`\b401\b|["']authorization["']|getKindeServerSession|lucia|currentUserId|userId\s*=\s*await`,
    String.raw`Depends\(\s*(?:get_current_user|current_user|get_user|auth|verify|require|oauth2_scheme)`,
    String.raw`login_required|jwt_required|requires_auth|current_user|HTTPBearer|OAuth2PasswordBearer`,
    String.raw`Security\(|IsAuthenticated|permission_classes`,
  ].join("|"),
  "i",
);
const MIDDLEWARE_AUTH =
  /clerkMiddleware|authMiddleware|withAuth|NextAuth|auth\(|getToken\(|updateSession|createServerClient|kindeMiddleware/;
const PY_MUTATION_ROUTE =
  /@\w+\.(?:post|put|patch|delete)\s*\(|@\w+\.route\([^)]*methods\s*=\s*\[[^\]]*['"](?:POST|PUT|PATCH|DELETE)['"]/;
const PY_DATA_CHANGE =
  /\.(?:add|commit|delete|insert|update|upsert|save|create)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i;

interface Project {
  root: string;
  files: string[];
  packageJson: string;
  supabase: boolean;
  firebase: boolean;
  vite: boolean;
  middlewareAuth?: string;
}

function rel(project: Project, file: string): string {
  return (relative(project.root, file) || basename(file)).split(sep).join("/");
}

function read(file: string): string {
  try {
    if (statSync(file).size > MAX_FILE) return "";
    return readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function ext(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i).toLowerCase() : "";
}

function walk(dir: string, out: string[], depth = 0): void {
  if (depth > 20) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    const full = join(dir, name);
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(name)) walk(full, out, depth + 1);
    } else out.push(full);
  }
}

export function discover(target: string): Project {
  const abs = resolve(target);
  const isDir = statSync(abs).isDirectory();
  const project: Project = {
    root: isDir ? abs : dirname(abs),
    files: [],
    packageJson: "",
    supabase: false,
    firebase: false,
    vite: false,
  };
  if (isDir) walk(abs, project.files);
  else project.files.push(abs);
  for (const file of project.files) {
    const name = basename(file);
    if (name === "package.json" && !project.packageJson) project.packageJson = read(file);
    if (name.startsWith("vite.config.")) project.vite = true;
    if (["firebase.json", "firestore.rules", "storage.rules", "database.rules.json"].includes(name)) project.firebase = true;
    if (name === "config.toml" && basename(dirname(file)) === "supabase") project.supabase = true;
    if ((name === "middleware.ts" || name === "middleware.js") && !project.middlewareAuth && MIDDLEWARE_AUTH.test(read(file))) {
      project.middlewareAuth = rel(project, file);
    }
  }
  const pkg = project.packageJson;
  project.supabase ||=
    pkg.includes("@supabase/") || project.files.some((f) => ext(f) === ".sql" && rel(project, f).split("/").includes("supabase"));
  project.vite ||= pkg.includes('"vite"');
  project.firebase ||= pkg.includes('"firebase"') || pkg.includes('"firebase-admin"');
  return project;
}

function finding(
  ruleId: string,
  title: string,
  severity: Severity,
  file: string,
  line: number,
  description: string,
  fix: string,
  confidence: Confidence = "high",
): Finding {
  return { title, severity, tool: TOOL, file, line, ruleId, description, fix, confidence };
}

function checkEnvFiles(project: Project): Finding[] {
  const rule = SHARED_RULES.find((r) => r.id === "vibe-public-env-secret");
  if (!rule) return [];
  const name = new RegExp(`^(?:${rule.source})$`, rule.flags);
  const out: Finding[] = [];
  for (const file of project.files) {
    const base = basename(file);
    if (!(base === ".env" || base.startsWith(".env.")) || /\.(?:example|sample|template|dist)$/.test(base)) continue;
    read(file).split("\n").forEach((line, i) => {
      const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (!m || !m[2].trim().replace(/^['"]|['"]$/g, "")) return;
      if (!name.test(m[1])) return;
      out.push(
        finding(
          "vibe-public-env-secret",
          `${m[1]} is a secret in a public env variable — it's bundled into the website`,
          "high",
          rel(project, file),
          i + 1,
          `Variables with this prefix are copied into the JavaScript every visitor downloads, so ${m[1]} can be read in the browser's dev tools.`,
          rule.fixGuidance,
        ),
      );
    });
  }
  return out;
}

function checkSupabaseRls(project: Project): Finding[] {
  if (!project.supabase) return [];
  const created = new Map<string, [string, number]>();
  const enabled = new Set<string>();
  const sqlFiles = project.files
    .filter((f) => ext(f) === ".sql" && pathContext(rel(project, f)) !== "test")
    .sort((a, b) => rel(project, a).localeCompare(rel(project, b)));
  for (const file of sqlFiles) {
    const text = read(file);
    const loops = [...text.matchAll(ENABLE_RLS_LOOP)].map((m) => m.index ?? 0);
    const here = new Map<string, number>();
    for (const m of text.matchAll(CREATE_TABLE)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      const table = m[2].toLowerCase();
      if (!created.has(table)) created.set(table, [rel(project, file), lineOf(text, m.index ?? 0)]);
      if (!here.has(table)) here.set(table, m.index ?? 0);
    }
    if (loops.length) {
      const last = loops[loops.length - 1];
      for (const table of created.keys()) {
        const pos = here.get(table);
        if (pos === undefined || pos < last) enabled.add(table);
      }
    }
    for (const m of text.matchAll(ENABLE_RLS)) {
      if ((m[1] ?? "public").toLowerCase() === "public") enabled.add(m[2].toLowerCase());
    }
  }
  return [...created.entries()]
    .filter(([table]) => !enabled.has(table))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([table, [file, line]]) =>
      finding(
        "vibe-supabase-table-without-rls",
        `Table ${table} has no Row Level Security — anyone with your public key can read and change it`,
        "high",
        file,
        line,
        "Supabase tables in the public schema are reachable with the anon key that ships in your app. Without RLS, that key can read, change and delete every row.",
        `alter table public.${table} enable row level security; then add policies for who may read and write, e.g. using (auth.uid() = user_id).`,
      ),
    );
}

function checkFirebaseRules(project: Project): Finding[] {
  const out: Finding[] = [];
  for (const file of project.files) {
    const name = basename(file);
    const path = rel(project, file);
    if (name.endsWith(".rules")) {
      const text = read(file);
      for (const m of text.matchAll(FIRESTORE_OPEN)) {
        out.push(
          finding(
            "vibe-firebase-rules-open",
            "Firebase rules let anyone read or write — your data is public",
            "critical",
            path,
            lineOf(text, m.index ?? 0),
            "An allow rule with no condition (or `if true`) applies to every visitor, logged in or not.",
            "Only allow signed-in users to their own data: allow read, write: if request.auth != null && request.auth.uid == userId;",
          ),
        );
      }
      for (const m of text.matchAll(FIRESTORE_TEST_MODE)) {
        out.push(
          finding(
            "vibe-firebase-test-mode",
            "Firebase rules are still in test mode — open to everyone until the date in the rule",
            "high",
            path,
            lineOf(text, m.index ?? 0),
            "Test-mode rules allow all reads and writes until a date, then lock you out. Until then the database is public.",
            "Replace the time check with real rules based on request.auth.",
          ),
        );
      }
    } else if (name === "database.rules.json") {
      const text = read(file);
      for (const m of text.matchAll(RTDB_OPEN)) {
        out.push(
          finding(
            "vibe-firebase-rules-open",
            "Realtime Database rules let anyone read or write — your data is public",
            "critical",
            path,
            lineOf(text, m.index ?? 0),
            '".read": true / ".write": true applies to every visitor.',
            'Use rules based on auth: ".read": "auth != null && auth.uid === $uid".',
          ),
        );
      }
    }
  }
  return out;
}

function isBrowserFile(project: Project, file: string, text: string): boolean {
  if (!BROWSER_EXT.has(ext(file))) return false;
  if (USE_CLIENT.test(text.slice(0, 500))) return true;
  const parts = rel(project, file).split("/");
  // Server-only by convention: *.server.ts, server/api dirs, Supabase / Netlify / Firebase functions.
  if (basename(file).toLowerCase().includes(".server.")) return false;
  const serverDirs = new Set(["server", "api", "functions", "edge-functions", "netlify", "scripts"]);
  if (parts.slice(0, -1).some((p) => serverDirs.has(p))) return false;
  if (project.vite && parts[0] === "src") return true;
  return parts[0] === "components" || rel(project, file).startsWith("src/components/");
}

function checkServiceRoleInBrowser(project: Project): Finding[] {
  if (!project.supabase) return [];
  const out: Finding[] = [];
  for (const file of project.files) {
    const path = rel(project, file);
    if (pathContext(path) || !CODE_EXT.has(ext(file))) continue;
    const text = read(file);
    if (!text || !isBrowserFile(project, file, text)) continue;
    const m = SERVICE_ROLE_REF.exec(text);
    if (m) {
      out.push(
        finding(
          "vibe-supabase-service-role-in-browser",
          "Supabase service_role key used in browser code — it bypasses every database rule",
          "critical",
          path,
          lineOf(text, m.index),
          "This file runs in the visitor's browser. Whatever key it uses can be copied from there, and service_role ignores Row Level Security.",
          "Use the anon key in browser code. Do privileged work in a server route or edge function that reads the service key from a server-only env variable, and rotate it.",
        ),
      );
    }
  }
  return out;
}

function checkUnprotectedMutations(project: Project): Finding[] {
  const out: Finding[] = [];
  const confidence: Confidence = project.middlewareAuth ? "low" : "medium";
  const note = project.middlewareAuth
    ? ` (${project.middlewareAuth} has an auth check; make sure it covers this route)`
    : "";
  for (const file of project.files) {
    const path = rel(project, file);
    const suffix = ext(file);
    if (!CODE_EXT.has(suffix) || pathContext(path)) continue;
    const text = read(file);
    const changesData = DATA_CHANGE.test(text) || (suffix === ".py" && PY_DATA_CHANGE.test(text));
    if (!text || !changesData || AUTH_EVIDENCE.test(text)) continue;
    let location: [number, string] | undefined;
    if (suffix === ".py") {
      const m = PY_MUTATION_ROUTE.exec(text);
      if (m && PY_DATA_CHANGE.test(text)) location = [lineOf(text, m.index), "endpoint"];
    } else {
      const name = basename(file).replace(/\.[^.]+$/, "");
      const m = ROUTE_MUTATION.exec(text);
      if (m && (name === "route" || `/${path}`.includes("/api/"))) {
        location = [lineOf(text, m.index), `${m[1] ?? m[2]} handler`];
      } else if ((path.startsWith("pages/api/") || path.startsWith("src/pages/api/")) && text.includes("export default")) {
        location = [lineOf(text, text.indexOf("export default")), "API route"];
      } else if (USE_SERVER.test(text.slice(0, 500))) {
        const action = SERVER_ACTION.exec(text);
        if (action) location = [lineOf(text, action.index), "server action"];
      }
    }
    if (location) {
      out.push(
        finding(
          "vibe-unprotected-mutation",
          `This ${location[1]} changes data but never checks who is calling it`,
          "high",
          path,
          location[0],
          "Anyone can call it directly (curl, the browser console), even if your UI only shows the button to logged-in users or admins." + note,
          "Check the user at the top of the handler (e.g. const user = await getUser(); if (!user) return 401) and that they own the record they change.",
          confidence,
        ),
      );
    }
  }
  return out;
}

export function vibeFindings(target: string): Finding[] {
  const project = discover(target);
  return [
    ...checkEnvFiles(project),
    ...checkSupabaseRls(project),
    ...checkFirebaseRules(project),
    ...checkServiceRoleInBrowser(project),
    ...checkUnprotectedMutations(project),
  ];
}

export async function runVibeChecks(target: string): Promise<ScanResult> {
  const result: ScanResult = { tool: TOOL, scanType: "sast", target, findings: [], errors: [] };
  try {
    result.findings = vibeFindings(target);
  } catch (err) {
    result.errors.push(`argus-vibe error: ${err instanceof Error ? err.message : String(err)}`);
  }
  return result;
}

export async function runVibeScan(target: string): Promise<ScanResult[]> {
  const results = await Promise.all([
    runVibeChecks(target),
    runNativeSast(target),
    runPatternSecrets(target),
    runPiiScan(target),
  ]);
  for (const r of results) r.errors = r.errors.filter((e) => e !== "No source files found to scan");
  return results;
}

// --- score, verdict and fix prompts (kept in step with vibe_report.py) ---------------------

type Level = "critical" | "high" | "moderate" | "low";
const WEIGHT: Record<Level, number> = { critical: 25, high: 12, moderate: 5, low: 1 };
const ORDER: Level[] = ["critical", "high", "moderate", "low"];
const NOT_SHIPPED = new Set(["test", "docs", "generated", "example"]);
const SKIP_RULES =
  /^(?:weak-crypto|redos-|pci-|sql-grant-all$|db-sql-dynamic-exec$|gha-|malware-|pii-hardcoded-(?:email|phone|name|address))/;
const FALLBACK_FIX: Array<[string, string]> = [
  ["xss-", "Don't insert HTML built from user data. Render text with React/Vue (no dangerouslySetInnerHTML / innerHTML), or clean it with DOMPurify first."],
  ["hardcoded-", "Move the value to a server-only environment variable, remove it from the code and git history, and rotate it."],
  ["sql", "Use parameterized queries (placeholders like $1 or ?) or your ORM's query builder; never paste user input into SQL text."],
  ["cors-", "Allow only your own site's origin instead of *."],
  ["open-redirect", "Only redirect to paths on your own site, or to a fixed list of URLs."],
  ["command-", "Don't build shell commands from user input; call the program with an argument list and validate the input."],
];
const SECRET_TOKENS = new RegExp(
  [
    String.raw`\bAKIA[0-9A-Z]{16}\b`,
    String.raw`\bgh[pousr]_[A-Za-z0-9]{36,}\b`,
    String.raw`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`,
    String.raw`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b`,
    String.raw`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`,
    String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`,
    String.raw`\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{16,}`,
    String.raw`\bAIza[0-9A-Za-z_-]{35}\b`,
    String.raw`\bsb_secret_[A-Za-z0-9_-]{16,}`,
  ].join("|"),
  "g",
);
const SECRET_ASSIGNMENT =
  /((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*)(["'])(?!\[REDACTED)([^"'\n]{4,})\2/gi;
const ENV_LINE = /^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$/;

export const VERDICTS: Array<[number, string, string]> = [
  [90, "Looks good to launch", "No serious problems found by these checks."],
  [70, "Fix a few things before launch", "Fix the items below, starting at the top."],
  [40, "Not safe to launch yet", "Attackers could reach your data or your bill."],
  [0, "Stop: your app is exposed", "Fix the top items before anyone uses it."],
];

/** Remove secret values from text that will be pasted into an AI chat. */
export function maskForPrompt(text: string, envFile = false): string {
  let out = envFile ? text.split("\n").map((l) => l.replace(ENV_LINE, "$1<value hidden>")).join("\n") : text;
  out = out.replace(SECRET_TOKENS, "[REDACTED:SECRET]");
  return out.replace(SECRET_ASSIGNMENT, "$1$2[REDACTED:SECRET]$2");
}

function excerpt(root: string, file: string, line: number, context = 2): string {
  if (!file || line <= 0) return "";
  const path = resolve(root, file);
  const inside = relative(root, path);
  if (inside.startsWith("..") || isAbsolute(inside)) return "";
  let lines: string[];
  try {
    lines = readFileSync(path, "utf8").split("\n");
  } catch {
    return "";
  }
  const start = Math.max(0, line - 1 - context);
  const end = Math.min(lines.length, line + context);
  const width = String(end).length;
  const envFile = basename(path).startsWith(".env");
  const out: string[] = [];
  for (let n = start; n < end; n++) {
    out.push(`${String(n + 1).padStart(width)} | ${maskForPrompt(lines[n].slice(0, 200), envFile)}`);
  }
  return out.join("\n");
}

export interface VibeItem {
  severity: Level;
  confidence: Confidence;
  ruleId: string;
  title: string;
  file: string;
  line: number;
  explanation: string;
  fix: string;
  prompt: string;
}

export interface VibeSummary {
  score: number;
  verdict: string;
  detail: string;
  counts: Record<Level, number>;
  notShipped: number;
  items: VibeItem[];
}

function explanation(description: string): string {
  const kept = description
    .split("\n")
    .filter((l) => l.trim() && !/^(?:Language:|To ignore|Suppress)/.test(l));
  return maskForPrompt(kept.join("\n")).trim();
}

export function fixPrompt(item: Omit<VibeItem, "prompt">, code: string): string {
  const where = item.line ? `${item.file} (line ${item.line})` : item.file || "project";
  const parts = ["Fix this security issue in my app.", "", `File: ${where}`, `Problem: ${item.title}`];
  if (item.explanation) parts.push(item.explanation);
  if (code) parts.push("", "Code:", "```", code, "```");
  if (item.fix) parts.push("", `What to change: ${item.fix}`);
  parts.push(
    "",
    "Change only what is needed and keep the app working. Never put secret values in code or in client-side env variables; read them from server-only environment variables. Tell me if a key has to be rotated.",
  );
  return parts.join("\n");
}

export function vibeSummary(results: ScanResult[], root: string): VibeSummary {
  const base = (() => {
    try {
      return statSync(root).isDirectory() ? resolve(root) : dirname(resolve(root));
    } catch {
      return resolve(root);
    }
  })();
  const seen = new Set<string>();
  const items: VibeItem[] = [];
  let notShipped = 0;
  for (const result of results) {
    for (const f of result.findings) {
      const severity = f.severity as Level;
      if (!(severity in WEIGHT)) continue;
      const ruleId = f.ruleId ?? "";
      if (SKIP_RULES.test(ruleId)) continue;
      if (f.context && NOT_SHIPPED.has(f.context)) {
        notShipped++;
        continue;
      }
      const key = `${f.file ?? ""}:${f.line ?? 0}:${ruleId || f.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fix = f.fix || FALLBACK_FIX.find(([prefix]) => ruleId.startsWith(prefix))?.[1] || "";
      const item = {
        severity,
        confidence: f.confidence ?? "medium",
        ruleId,
        title: maskForPrompt(f.title),
        file: f.file ?? "",
        line: f.line ?? 0,
        explanation: explanation(f.description ?? ""),
        fix: maskForPrompt(fix).trim(),
      };
      items.push({ ...item, prompt: fixPrompt(item, excerpt(base, item.file, item.line)) });
    }
  }
  items.sort(
    (a, b) =>
      ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) ||
      Number(a.confidence === "low") - Number(b.confidence === "low") ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  // Each repeat of a rule costs a third of the first, up to three times one finding.
  const perRule = new Map<string, number>();
  for (const item of items) {
    let weight = WEIGHT[item.severity];
    if (item.confidence === "low") weight /= 4;
    const rule = item.ruleId || item.title;
    const cost = perRule.has(rule) ? weight / 3 : weight;
    perRule.set(rule, Math.min((perRule.get(rule) ?? 0) + cost, weight * 3));
  }
  const penalty = [...perRule.values()].reduce((a, b) => a + b, 0);
  let score = Math.max(0, Math.round(100 - penalty));
  if (items.some((i) => i.severity === "critical" && i.confidence !== "low")) score = Math.min(score, 39);
  const [, verdict, detail] = VERDICTS.find(([floor]) => score >= floor) ?? VERDICTS[VERDICTS.length - 1];
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 } as Record<Level, number>;
  for (const item of items) counts[item.severity]++;
  return { score, verdict, detail, counts, notShipped, items };
}

const ICON: Record<Level, string> = { critical: "🔴", high: "🟠", moderate: "🟡", low: "⚪" };

export function formatVibeReport(summary: VibeSummary, target = "", showPrompts = true): string {
  const lines = [
    `Launch check${target ? `: ${basename(target)}` : ""}`,
    "",
    `Safety score: ${summary.score}/100. ${summary.verdict}. ${summary.detail}`,
    ORDER.map((s) => `${ICON[s]} ${summary.counts[s]} ${s === "moderate" ? "medium" : s}`).join(" · "),
  ];
  if (summary.notShipped) lines.push(`${summary.notShipped} finding(s) in tests, docs or examples not counted.`);
  if (!summary.items.length) {
    lines.push("", "No problems found by these checks. Keep secrets out of client code as you build.");
    return lines.join("\n");
  }
  summary.items.forEach((item, i) => {
    const where = item.line ? `${item.file}:${item.line}` : item.file;
    const maybe = item.confidence === "low" ? " (worth a look, may be fine)" : "";
    lines.push("", `${i + 1}. ${ICON[item.severity]} ${item.title}${maybe}`, `   ${where}`);
    if (item.explanation) lines.push(`   ${item.explanation}`);
    if (item.fix) lines.push(`   Fix: ${item.fix}`);
    if (showPrompts) {
      lines.push("", "   --- prompt for your AI tool ---", ...item.prompt.split("\n").map((l) => `   ${l}`), "   ---");
    }
  });
  return lines.join("\n");
}
