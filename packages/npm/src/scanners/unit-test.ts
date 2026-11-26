/**
 * `argus-codescan unit-test` (#276): is the app tested?
 *
 * Same checks, rule ids, score and prompts as argus-scan's `argus unit-test`
 * (argus/tools/testing_checks.py + argus/unit_test_report.py). Reads files, runs nothing.
 */

import { basename, dirname } from "node:path";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import type { Confidence, Finding, ScanResult } from "./types.js";
import {
  DATA_CHANGE,
  PY_DATA_CHANGE,
  PY_MUTATION_ROUTE,
  ROUTE_MUTATION,
  SERVER_ACTION,
  USE_SERVER,
  discover,
  excerpt,
  explanation,
  ext,
  lineOf,
  maskForPrompt,
  penalty,
  read,
  rel,
  type Level,
  type Project,
} from "./vibe.js";

const TOOL = "argus-tests";
const SOURCE_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py"]);
const UI_EXT = new Set([".tsx", ".jsx", ".vue", ".svelte", ".astro"]);
const TEST_FILE = /(?:\.(?:test|spec|e2e|cy)\.[cm]?[jt]sx?$|^test_.*\.py$|_test\.py$|^conftest\.py$)/;
const TEST_DIRS = new Set(["__tests__", "tests", "test", "e2e", "cypress", "playwright", "spec"]);
const JS_RUNNERS: Array<[string, string]> = [
  ["vitest", "vitest"],
  ["jest", "jest"],
  ["@playwright/test", "Playwright"],
  ["cypress", "Cypress"],
  ["mocha", "mocha"],
  ["ava", "ava"],
  ["uvu", "uvu"],
  ["@testing-library/", "Testing Library"],
];
const SCRIPT_RUNNERS: Array<[RegExp, string]> = [
  [/\bnode\b[^&|;]*--test\b/, "node:test"],
  [/\btsx\b[^&|;]*--test\b/, "node:test"],
  [/\bbun\s+test\b/, "bun test"],
  [/\bdeno\s+test\b/, "deno test"],
];
const E2E_DEPS = ["@playwright/test", "playwright", "cypress", "puppeteer", "@wdio/"];
const PLACEHOLDER_TEST = /no test specified/i;
const ASSERTION =
  /\bexpect\s*\(|\bassert\b|\.should\b|\bt\.(?:is|true|false|deepEqual|equal|throws)\b|\bpytest\.raises\b|\bself\.assert\w*\(|\.toBe\w*\(|\.toEqual\(|\.toMatch\w*\(/;
const JS_TEST_CASE = /\b(?:it|test)\s*\(/;
const PY_TEST_CASE = /^\s*(?:async\s+)?def\s+test_\w*\s*\(/m;
const FOCUSED = /\b(?:it|test|describe|context)\.only\s*\(|\bf(?:it|describe)\s*\(/;
const SKIPPED =
  /\b(?:it|test|describe|context)\.skip\s*\(|\bx(?:it|describe|test)\s*\(|@pytest\.mark\.skip\b|@unittest\.skip\b/;
const CI_RUNS_TESTS =
  /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|\bnpx\s+(?:vitest|jest|playwright|cypress)\b|\bvitest\b|\bjest\b|\bpytest\b|\bplaywright\s+test\b|\bcypress\s+run\b|\bunittest\b|\bmake\s+test\b|\btox\b|\bnox\b|\buv\s+run\s+pytest\b/;
const CI_FILE =
  /^(?:\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.circleci\/config\.yml|bitbucket-pipelines\.yml|azure-pipelines\.yml|\.travis\.yml)$/;
const CRITICAL_PAGE =
  /(?:^|\/)(?:login|log-in|signin|sign-in|signup|sign-up|register|checkout|billing|subscribe|pricing|reset-password|forgot-password)(?:\/|\.|$)/i;
const GENERIC_STEMS = new Set(["route", "index", "page", "actions", "action", "main", "app", "server", "api"]);
const PY_PROJECT_FILES = new Set(["pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.cfg", "Pipfile", "setup.py"]);

function isTestFile(path: string): boolean {
  const parts = path.split("/");
  return TEST_FILE.test(parts[parts.length - 1]) || parts.slice(0, -1).some((p) => TEST_DIRS.has(p));
}

function pythonProject(project: Project): string {
  return project.files
    .filter((f) => PY_PROJECT_FILES.has(basename(f)) && dirname(f) === project.root)
    .map((f) => read(f))
    .join("\n");
}

function parsePackage(text: string): Record<string, unknown> {
  try {
    const data = JSON.parse(text || "{}");
    return data && typeof data === "object" ? data : {};
  } catch {
    return {};
  }
}

function scripts(text: string): Record<string, string> {
  const s = parsePackage(text).scripts;
  return s && typeof s === "object" ? Object.fromEntries(Object.entries(s).map(([k, v]) => [k, String(v)])) : {};
}

function deps(text: string): string[] {
  const data = parsePackage(text);
  return ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].flatMap((k) => {
    const section = data[k];
    return section && typeof section === "object" ? Object.keys(section) : [];
  });
}

export function detectRunner(project: Project): string {
  const testScript = scripts(project.packageJson).test ?? "";
  for (const [pattern, name] of SCRIPT_RUNNERS) if (pattern.test(testScript)) return name;
  const names = deps(project.packageJson);
  for (const [dep, name] of JS_RUNNERS) if (names.some((d) => d === dep || d.startsWith(dep))) return name;
  return /\bpytest\b/.test(pythonProject(project)) ? "pytest" : "";
}

function setupHint(project: Project, runner: string): string {
  if (runner) return `Use ${runner}, which is already set up.`;
  if (project.packageJson) return 'Set up vitest first: npm i -D vitest, and add "test": "vitest run" to the scripts in package.json.';
  return "Set up pytest first: add pytest to your dev dependencies.";
}

function finding(
  ruleId: string,
  title: string,
  severity: Level,
  file: string,
  line: number,
  description: string,
  fix: string,
  confidence: Confidence = "high",
): Finding {
  return { title, severity, tool: TOOL, file, line, ruleId, description, fix, confidence };
}

function mutations(project: Project, sources: string[]): Array<[string, number, string]> {
  const out: Array<[string, number, string]> = [];
  for (const file of sources) {
    const path = rel(project, file);
    const text = read(file);
    if (!text) continue;
    if (ext(file) === ".py") {
      const m = PY_MUTATION_ROUTE.exec(text);
      if (m && PY_DATA_CHANGE.test(text)) out.push([path, lineOf(text, m.index), "endpoint"]);
      continue;
    }
    if (!DATA_CHANGE.test(text)) continue;
    const stem = basename(file).replace(/\.[^.]+$/, "");
    const m = ROUTE_MUTATION.exec(text);
    if (m && (stem === "route" || `/${path}`.includes("/api/"))) {
      out.push([path, lineOf(text, m.index), `${m[1] ?? m[2]} handler`]);
    } else if ((path.startsWith("pages/api/") || path.startsWith("src/pages/api/")) && text.includes("export default")) {
      out.push([path, lineOf(text, text.indexOf("export default")), "API route"]);
    } else if (USE_SERVER.test(text.slice(0, 500))) {
      const action = SERVER_ACTION.exec(text);
      if (action) out.push([path, lineOf(text, action.index), "server action"]);
    }
  }
  return out;
}

/** What a test for this file would mention: `orders` for app/api/orders/route.ts. */
function keyFor(path: string): string {
  const parts = path.split("/");
  const stem = parts[parts.length - 1].replace(/\.[^.]+$/, "");
  if (!GENERIC_STEMS.has(stem)) return stem;
  const named = parts.slice(0, -1).filter((p) => !p.startsWith("(") && !p.startsWith("[") && !["app", "src", "api", "pages"].includes(p));
  return named[named.length - 1] ?? "";
}

function escapeRe(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface TestingMeta {
  app: boolean;
  runner?: string;
  testFiles?: number;
  sourceFiles?: number;
}

export function findTestingGaps(target: string): { findings: Finding[]; meta: TestingMeta } {
  const project = discover(target);
  const pyDeps = pythonProject(project);
  if (!project.packageJson && !pyDeps) return { findings: [], meta: { app: false } };

  const rels = new Map(project.files.map((f) => [f, rel(project, f)]));
  const tests = project.files.filter((f) => SOURCE_EXT.has(ext(f)) && isTestFile(rels.get(f)!));
  const sources = project.files.filter(
    (f) => SOURCE_EXT.has(ext(f)) && !isTestFile(rels.get(f)!) && !/\.(?:d\.ts|config\.[cm]?[jt]s)$/.test(f),
  );
  const runner = detectRunner(project);
  const setup = setupHint(project, runner);
  const findings: Finding[] = [];
  const meta: TestingMeta = { app: true, runner, testFiles: tests.length, sourceFiles: sources.length };

  const pkg = project.packageJson;
  if (pkg && PLACEHOLDER_TEST.test(scripts(pkg).test ?? "")) {
    findings.push(
      finding(
        "tests-placeholder-script",
        '"npm test" is the placeholder script — no tests run',
        "moderate",
        "package.json",
        lineOf(pkg, pkg.indexOf('"test"')),
        'The test script still says "Error: no test specified", so npm test and any CI step that calls it check nothing.',
        `${setup} Point the "test" script at it (e.g. "test": "vitest run").`,
      ),
    );
  }
  if (!tests.length && sources.length >= 3) {
    findings.push(
      finding(
        "tests-none",
        `No tests: ${sources.length} source files and not one test file`,
        "moderate",
        pkg ? "package.json" : "",
        0,
        "Every change your AI tool makes could break login, payments or saving data, and nothing would tell you before your users do.",
        `${setup} Start with the code that saves or deletes data, then the login flow.`,
      ),
    );
  } else if (tests.length && !runner && pkg && !pyDeps) {
    findings.push(
      finding(
        "tests-no-runner",
        "Test files exist but no test runner is installed",
        "low",
        "package.json",
        0,
        "package.json has no vitest, jest, mocha or Playwright, so these tests probably can't run.",
        setup,
      ),
    );
  }

  // A test "covers" a file when its name or its text mentions it (orders.test.ts, '/api/orders').
  const testText = tests.map((f) => `${rels.get(f)}\n${read(f)}`).join("\n");
  for (const [path, line, what] of mutations(project, sources)) {
    const key = keyFor(path);
    if (tests.length && key && new RegExp(`\\b${escapeRe(key)}\\b`).test(testText)) continue;
    findings.push(
      finding(
        "tests-untested-mutation",
        `This ${what} changes data and has no test`,
        "moderate",
        path,
        line,
        "Code that writes to your database is where a small AI edit does the most damage: a dropped auth check or a wrong filter deletes or leaks other users' data.",
        `Write tests for ${path} (${what}). ${setup} Cover: a request with no logged-in user is rejected (401/403); a user can't change another user's records; a valid request by the owner works. Mock the database client.`,
      ),
    );
  }

  for (const file of tests) {
    const path = rels.get(file)!;
    const text = read(file);
    const cases = (ext(file) === ".py" ? PY_TEST_CASE : JS_TEST_CASE).exec(text);
    if (cases && !ASSERTION.test(text)) {
      findings.push(
        finding(
          "tests-no-assertions",
          "Test file has tests that check nothing (no expect / assert)",
          "low",
          path,
          lineOf(text, cases.index),
          "A test without an assertion passes whatever the code does. AI tools sometimes write these to make a failing suite go green.",
          "Add expect(...) / assert checks on the result, the response status and what was written to the database.",
        ),
      );
    }
    const focused = FOCUSED.exec(text);
    if (focused) {
      findings.push(
        finding(
          "tests-focused",
          ".only left in a test — every other test is silently skipped",
          "moderate",
          path,
          lineOf(text, focused.index),
          "With .only (or fit / fdescribe), the runner runs just this test and reports success for the whole suite.",
          "Remove .only. Many runners can fail on it in CI (vitest --allowOnly=false, jest --ci with eslint-plugin-jest no-focused-tests).",
        ),
      );
    }
    const skipped = SKIPPED.exec(text);
    if (skipped) {
      findings.push(
        finding(
          "tests-skipped",
          "Skipped test left in",
          "low",
          path,
          lineOf(text, skipped.index),
          "Skipped tests are often ones that started failing; the bug they found is still there.",
          "Fix the test or the code it found broken, then remove the skip.",
          "low",
        ),
      );
    }
  }

  const ciFiles = project.files.filter((f) => CI_FILE.test(rels.get(f)!));
  if (tests.length && ciFiles.length && !ciFiles.some((f) => CI_RUNS_TESTS.test(read(f)))) {
    const first = ciFiles.map((f) => rels.get(f)!).sort()[0];
    findings.push(
      finding(
        "tests-not-in-ci",
        "CI never runs your tests",
        "low",
        first,
        0,
        "The pipeline deploys without running the test suite, so a change that breaks tests still ships.",
        "Add a step before deploy that runs the tests (e.g. npm ci && npm test, or pytest) and fails the job when they fail.",
      ),
    );
  }

  const depNames = deps(pkg).join("\n");
  const hasE2e =
    E2E_DEPS.some((d) => depNames.includes(d)) ||
    tests.some((f) => {
      const p = rels.get(f)!;
      return p.split("/").includes("e2e") || p.includes("cypress") || p.includes("playwright");
    });
  const pages = sources
    .filter((f) => UI_EXT.has(ext(f)) && CRITICAL_PAGE.test(rels.get(f)!))
    .map((f) => rels.get(f)!)
    .sort();
  if (pkg && pages.length && !hasE2e) {
    findings.push(
      finding(
        "tests-no-e2e",
        "No end-to-end test for login, signup or checkout",
        "low",
        pages[0],
        0,
        `The app has ${pages.length} page(s) for signing in or paying (${pages.slice(0, 3).join(", ")}${pages.length > 3 ? "…" : ""}) and no browser test that walks through them.`,
        "Add Playwright (npm init playwright@latest) and one test per flow: sign up, log in, log out, and pay with a test card in your payment provider's test mode. Use test accounts, never real customer data.",
      ),
    );
  }
  return { findings, meta };
}

export async function runTestChecks(target: string): Promise<ScanResult & { meta: TestingMeta }> {
  const result: ScanResult & { meta: TestingMeta } = { tool: TOOL, scanType: "sast", target, findings: [], errors: [], meta: { app: false } };
  try {
    const { findings, meta } = findTestingGaps(target);
    result.findings = findings;
    result.meta = meta;
  } catch (err) {
    result.errors.push(`argus-tests error: ${err instanceof Error ? err.message : String(err)}`);
  }
  return result;
}

// --- score and prompts (kept in step with unit_test_report.py) ------------------------------

const WEIGHT: Record<Level, number> = { critical: 30, high: 20, moderate: 15, low: 6 };
const ORDER: Level[] = ["critical", "high", "moderate", "low"];
const VERDICTS: Array<[number, string, string]> = [
  [80, "Well tested", "The basics are covered."],
  [50, "Partly tested", "Add tests for the items below, starting at the top."],
  [20, "Barely tested", "Most of what could break has no test."],
  [0, "No real tests", "Nothing checks that your app still works after a change."],
];

export interface TestItem {
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

export interface TestsSummary {
  score: number | null;
  verdict: string;
  detail: string;
  runner: string;
  testFiles: number;
  sourceFiles: number;
  items: TestItem[];
}

export function testsPrompt(item: Omit<TestItem, "prompt">, code: string): string {
  const where = item.line ? `${item.file} (line ${item.line})` : item.file || "project";
  const parts = ["Improve the tests in my app.", "", `Where: ${where}`, `Problem: ${item.title}`];
  if (item.explanation) parts.push(item.explanation);
  if (code) parts.push("", "Code:", "```", code, "```");
  if (item.fix) parts.push("", `What to do: ${item.fix}`);
  parts.push(
    "",
    "Tests must check real behaviour with expect / assert, not just run the code. Don't call real databases, payment providers or email services: mock them or use test mode. Use made-up test data, never real customer data or real keys. Run the tests and show me they pass.",
  );
  return parts.join("\n");
}

export function testsSummary(result: ScanResult & { meta: TestingMeta }, root: string): TestsSummary {
  const meta = result.meta;
  if (!meta.app) {
    return {
      score: null,
      verdict: "Not an app project",
      detail: "No package.json or Python project file found, so there is nothing to check.",
      runner: "",
      testFiles: 0,
      sourceFiles: 0,
      items: [],
    };
  }
  let base = resolve(root);
  try {
    if (!statSync(base).isDirectory()) base = dirname(base);
  } catch {
    /* keep */
  }
  const items: TestItem[] = result.findings
    .filter((f) => (f.ruleId ?? "").startsWith("tests-") && f.severity in WEIGHT)
    .map((f) => {
      const item = {
        severity: f.severity as Level,
        confidence: f.confidence ?? "medium",
        ruleId: f.ruleId ?? "",
        title: maskForPrompt(f.title),
        file: f.file ?? "",
        line: f.line ?? 0,
        explanation: explanation(f.description ?? ""),
        fix: maskForPrompt(f.fix ?? "").trim(),
      };
      return { ...item, prompt: testsPrompt(item, excerpt(base, item.file, item.line)) };
    })
    .sort(
      (a, b) =>
        ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) ||
        Number(a.confidence === "low") - Number(b.confidence === "low") ||
        a.file.localeCompare(b.file) ||
        a.line - b.line,
    );
  let score = Math.max(0, Math.round(100 - penalty(items, WEIGHT)));
  if (items.some((i) => i.ruleId === "tests-none" || i.ruleId === "tests-placeholder-script")) {
    score = Math.min(score, meta.testFiles ? 40 : 10);
  }
  const [, verdict, detail] = VERDICTS.find(([floor]) => score >= floor) ?? VERDICTS[VERDICTS.length - 1];
  return {
    score,
    verdict,
    detail,
    runner: meta.runner ?? "",
    testFiles: meta.testFiles ?? 0,
    sourceFiles: meta.sourceFiles ?? 0,
    items,
  };
}

const ICON: Record<Level, string> = { critical: "🔴", high: "🟠", moderate: "🟡", low: "⚪" };

export function formatTestsReport(summary: TestsSummary, target = "", showPrompts = true): string {
  const lines = [`Unit test check${target ? `: ${basename(resolve(target))}` : ""}`, ""];
  if (summary.score === null) return [...lines, `${summary.verdict}. ${summary.detail}`].join("\n");
  lines.push(
    `Testing score: ${summary.score}/100. ${summary.verdict}. ${summary.detail}`,
    `${summary.testFiles} test file(s) for ${summary.sourceFiles} source file(s), ${summary.runner || "no test runner"}.`,
  );
  if (!summary.items.length) lines.push("", "Nothing missing that these checks look for.");
  summary.items.forEach((item, i) => {
    const where = item.line ? `${item.file}:${item.line}` : item.file;
    const maybe = item.confidence === "low" ? " (worth a look, may be fine)" : "";
    lines.push("", `${i + 1}. ${ICON[item.severity]} ${item.title}${maybe}`);
    if (where) lines.push(`   ${where}`);
    if (item.explanation) lines.push(`   ${item.explanation}`);
    if (item.fix) lines.push(`   What to do: ${item.fix}`);
    if (showPrompts) {
      lines.push("", "   --- prompt to write the tests ---", ...item.prompt.split("\n").map((l) => `   ${l}`), "   ---");
    }
  });
  return lines.join("\n");
}

/** `argus-codescan unit-test [path] [--format json] [--fail-under N]`. Returns the exit code. */
export async function runUnitTestCli(args: string[]): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
argus-codescan unit-test [path] — is your app tested? (reads files, runs nothing)

Checks: test runner, the placeholder "npm test", routes and server actions that change data
with no test, tests with no assertions, .only / .skip left in, CI that never runs tests,
no end-to-end test for login or checkout. Each item comes with a prompt that writes the tests.

OPTIONS:
  --format json|text     Output (default: text)
  --fail-under SCORE     Exit 1 when the testing score is below SCORE (0-100)
  --no-prompts           Leave the prompts out of the text output
`);
    return 0;
  }
  let format = "text";
  let failUnder: number | undefined;
  let prompts = true;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--format" && args[i + 1]) format = args[++i];
    else if (arg === "--fail-under" && args[i + 1]) failUnder = Number(args[++i]);
    else if (arg === "--no-prompts") prompts = false;
    else if (!arg.startsWith("-")) positional.push(arg);
  }
  const target = resolve(positional[0] ?? ".");
  try {
    statSync(target);
  } catch {
    console.error(`Not found: ${target}`);
    return 2;
  }
  console.error(`Checking tests in: ${target}`);
  const result = await runTestChecks(target);
  const summary = testsSummary(result, target);
  console.log(format === "json" ? JSON.stringify(summary, null, 2) : formatTestsReport(summary, target, prompts));
  if (failUnder !== undefined && summary.score !== null && summary.score < failUnder) {
    console.error(`Failed: testing score ${summary.score} is below ${failUnder}`);
    return 1;
  }
  return 0;
}
