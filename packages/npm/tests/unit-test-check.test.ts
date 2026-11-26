import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { findTestingGaps, runTestChecks, testsSummary } from "../src/scanners/unit-test.js";

// Same cases as argus-scan tests/test_unit_test_check.py (#276).
const ROUTE = "export async function DELETE(req: Request) {\n  await supabase.from('orders').delete().eq('id', id)\n}\n";

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "argus-ut-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), text);
  }
  return root;
}

function rules(root: string): Record<string, Array<[string, number]>> {
  const out: Record<string, Array<[string, number]>> = {};
  for (const f of findTestingGaps(root).findings) (out[f.ruleId ?? ""] ??= []).push([f.file ?? "", f.line ?? 0]);
  for (const list of Object.values(out)) list.sort();
  return out;
}

const UNTESTED_APP = {
  "package.json": JSON.stringify({ scripts: { test: 'echo "Error: no test specified" && exit 1' }, dependencies: { next: "15" } }, null, 2),
  "app/api/orders/route.ts": ROUTE,
  "app/login/page.tsx": "export default function Login() { return null }\n",
  "app/page.tsx": "export default function Home() { return null }\n",
  "lib/util.ts": "export const x = 1\n",
};

describe("argus-codescan unit-test (#276)", () => {
  it("an untested app", () => {
    const found = rules(project(UNTESTED_APP));
    expect(found["tests-placeholder-script"]).toEqual([["package.json", 3]]);
    expect(found["tests-none"]).toEqual([["package.json", 0]]);
    expect(found["tests-untested-mutation"]).toEqual([["app/api/orders/route.ts", 1]]);
    expect(found["tests-no-e2e"]).toEqual([["app/login/page.tsx", 0]]);
  });

  it("a well-tested app", () => {
    const root = project({
      "package.json": JSON.stringify({ scripts: { test: "vitest run" }, devDependencies: { vitest: "2", "@playwright/test": "1" } }),
      "app/api/orders/route.ts": ROUTE,
      "app/login/page.tsx": "export default function Login() { return null }\n",
      "tests/orders.test.ts": "it('rejects anonymous', () => { expect(1).toBe(1) })\n",
      ".github/workflows/ci.yml": "steps:\n  - run: npm ci && npm test\n",
    });
    expect(rules(root)).toEqual({});
  });

  it("test quality: no assertions, .only, .skip, CI", () => {
    const found = rules(
      project({
        "package.json": '{"devDependencies": {"jest": "29"}}',
        "src/a.test.ts": "test('runs', () => { doThing() })\n",
        "src/b.test.ts": "describe.only('x', () => { it('y', () => expect(1).toBe(1)) })\n",
        "src/c.test.ts": "it.skip('flaky', () => { expect(1).toBe(2) })\n",
        "tests/test_api.py": "def test_add():\n    add(1, 2)\n",
        ".github/workflows/deploy.yml": "steps:\n  - run: npm run build\n",
      }),
    );
    expect(found["tests-no-assertions"]).toEqual([["src/a.test.ts", 1], ["tests/test_api.py", 1]]);
    expect(found["tests-focused"]).toEqual([["src/b.test.ts", 1]]);
    expect(found["tests-skipped"]).toEqual([["src/c.test.ts", 1]]);
    expect(found["tests-not-in-ci"]).toEqual([[".github/workflows/deploy.yml", 0]]);
  });

  it("a route counts as tested when a test mentions it; node --test is a runner", () => {
    const found = rules(
      project({
        "package.json": '{"scripts": {"test": "node --test"}}',
        "app/api/orders/route.ts": ROUTE,
        "app/api/invoices/route.ts": ROUTE.replace("orders", "invoices"),
        "tests/orders.test.ts": "import { DELETE } from '../app/api/orders/route'\nit('x', () => { expect(DELETE).toBeDefined() })\n",
      }),
    );
    expect(found["tests-untested-mutation"]).toEqual([["app/api/invoices/route.ts", 1]]);
    expect(found["tests-no-runner"]).toBeUndefined();
  });

  it("Python projects, non-apps and DTOs named login", () => {
    const py = project({
      "pyproject.toml": "[project]\nname='x'\n[dependency-groups]\ndev=['pytest']\n",
      "app/main.py": "@app.post('/items')\ndef add(item):\n    db.add(item)\n    db.commit()\n",
      "tests/test_main.py": "def test_add():\n    assert add_item() == 1\n",
    });
    expect(rules(py)).toEqual({ "tests-untested-mutation": [["app/main.py", 1]] });
    expect(findTestingGaps(project({ "notes.md": "# hi\n" }))).toEqual({ findings: [], meta: { app: false } });
    const dto = project({
      "package.json": '{"devDependencies": {"jest": "29"}}',
      "src/auth/dto/login.dto.ts": "export class LoginDto {}\n",
      "src/app.spec.ts": "it('x', () => expect(1).toBe(1))\n",
    });
    expect(rules(dto)["tests-no-e2e"]).toBeUndefined();
  });

  it("score, verdict and prompts like argus-scan", async () => {
    const root = project(UNTESTED_APP);
    const summary = testsSummary(await runTestChecks(root), root);
    expect([summary.score, summary.verdict]).toEqual([10, "No real tests"]);
    const route = summary.items.find((i) => i.ruleId === "tests-untested-mutation")!;
    expect(route.prompt).toContain("Improve the tests in my app.");
    expect(route.prompt).toContain("Set up vitest first");
    expect(route.prompt).toContain("a user can't change another user's records");
    expect(route.prompt).toContain("Code:");
    const notApp = project({ "a.md": "x" });
    expect(testsSummary(await runTestChecks(notApp), notApp).score).toBeNull();
  });
});
