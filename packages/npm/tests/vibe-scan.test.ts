import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "../src/scanners/types.js";
import { maskForPrompt, runVibeScan, vibeFindings, vibeSummary } from "../src/scanners/vibe.js";

// Same cases as argus-scan tests/test_vibe_checks.py and tests/test_vibe_report.py (#272, #273).
const OPENAI_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2";

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "argus-vibe-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), text);
  }
  return root;
}

function byRule(root: string): Record<string, Array<[string, number]>> {
  const out: Record<string, Array<[string, number]>> = {};
  for (const f of vibeFindings(root)) (out[f.ruleId ?? ""] ??= []).push([f.file ?? "", f.line ?? 0]);
  return out;
}

const LOVABLE_APP = {
  "package.json": '{"dependencies": {"next": "15", "@supabase/supabase-js": "^2"}}',
  ".env.local": `NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=eyJanon\nNEXT_PUBLIC_OPENAI_API_KEY=${OPENAI_KEY}\nOPENAI_API_KEY=sk-proj-server\n`,
  ".env.example": "NEXT_PUBLIC_OPENAI_API_KEY=your-key-here\n",
  "supabase/migrations/001_init.sql":
    "create table public.profiles (id uuid primary key, email text);\n" +
    "alter table public.profiles enable row level security;\n" +
    "create table public.orders (id serial primary key, user_id uuid, total int);\n" +
    "create table if not exists private.audit (id int);\n",
  "app/admin/page.tsx":
    "'use client'\nimport { createClient } from '@supabase/supabase-js'\nconst s = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)\n",
  "app/api/orders/route.ts":
    "import { supabase } from '@/lib/supabase'\nexport async function DELETE(req: Request) {\n  const { id } = await req.json()\n  await supabase.from('orders').delete().eq('id', id)\n  return Response.json({ ok: true })\n}\n",
  "app/api/profile/route.ts":
    "export async function POST(req: Request) {\n  const { data: { user } } = await supabase.auth.getUser()\n  if (!user) return new Response('no', { status: 401 })\n  await supabase.from('profiles').update({ name }).eq('id', user.id)\n}\n",
  "app/actions.ts": "'use server'\nexport async function deletePost(id: string) {\n  await db.post.delete({ where: { id } })\n}\n",
};

describe("vibe project checks (#272)", () => {
  it("finds the usual AI-built app failures", () => {
    const found = byRule(project(LOVABLE_APP));
    expect(found["vibe-public-env-secret"]).toEqual([[".env.local", 3]]);
    expect(found["vibe-supabase-table-without-rls"]).toEqual([["supabase/migrations/001_init.sql", 3]]);
    expect(found["vibe-supabase-service-role-in-browser"]).toEqual([["app/admin/page.tsx", 3]]);
    expect(found["vibe-unprotected-mutation"].sort()).toEqual([
      ["app/actions.ts", 2],
      ["app/api/orders/route.ts", 2],
    ]);
  });

  it("never prints secret values", () => {
    const text = JSON.stringify(vibeFindings(project(LOVABLE_APP)));
    expect(text).not.toContain(OPENAI_KEY);
  });

  it("an RLS loop over pg_tables covers tables made before it", () => {
    const root = project({
      "supabase/config.toml": "",
      "supabase/migrations/001_init.sql":
        "create table public.clients (id int);\n" +
        "do $$ declare t text; begin\n  for t in select tablename from pg_tables where schemaname = 'public' loop\n" +
        "    execute format('alter table public.%I enable row level security', t);\n  end loop; end $$;\n" +
        "create table public.after_loop (id int);\n",
      "supabase/migrations/002_more.sql": "create table public.later (id int);\n",
    });
    const tables = vibeFindings(root)
      .filter((f) => f.ruleId === "vibe-supabase-table-without-rls")
      .map((f) => f.title.split(" ")[1]);
    expect(tables.sort()).toEqual(["after_loop", "later"]);
  });

  it("server-only files are not browser code", () => {
    const root = project({
      "package.json": '{"dependencies": {"vite": "5", "@supabase/supabase-js": "^2"}}',
      "src/integrations/supabase/client.server.ts": "createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)\n",
      "supabase/functions/admin/index.ts": "createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))\n",
      "src/pages/Admin.tsx": "createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n",
    });
    expect(byRule(root)["vibe-supabase-service-role-in-browser"]).toEqual([["src/pages/Admin.tsx", 1]]);
  });

  it("Firebase rules: open, test mode and safe", () => {
    const open = byRule(
      project({
        "firebase.json": "{}",
        "firestore.rules": "service cloud.firestore {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n",
        "storage.rules": "match /b/{bucket}/o {\n  allow read, write: if request.time < timestamp.date(2026, 12, 1);\n}\n",
        "database.rules.json": '{"rules": {".read": true, ".write": "auth != null"}}',
      }),
    );
    expect(open["vibe-firebase-rules-open"].sort()).toEqual([["database.rules.json", 1], ["firestore.rules", 3]]);
    expect(open["vibe-firebase-test-mode"]).toEqual([["storage.rules", 2]]);
    const safe = project({ "firestore.rules": "allow read, write: if request.auth != null && request.auth.uid == uid;\n" });
    expect(byRule(safe)).toEqual({});
  });

  it("middleware auth lowers confidence; Python endpoints are checked", () => {
    const withMw = vibeFindings(project({ ...LOVABLE_APP, "middleware.ts": "export default clerkMiddleware()\n" }));
    expect(withMw.filter((f) => f.ruleId === "vibe-unprotected-mutation").every((f) => f.confidence === "low")).toBe(true);
    const py = byRule(
      project({
        "api/open.py": "@app.post('/items')\ndef add(item: Item, db=Depends(get_db)):\n    db.add(Item(**item.dict()))\n    db.commit()\n",
        "api/safe.py": "@app.post('/items')\ndef add(item: Item, user=Depends(get_current_user)):\n    db.add(item)\n    db.commit()\n",
      }),
    );
    expect(py).toEqual({ "vibe-unprotected-mutation": [["api/open.py", 1]] });
  });
});

function result(...findings: Array<Partial<Finding> & Pick<Finding, "severity">>): ScanResult[] {
  return [
    {
      tool: "t",
      scanType: "sast",
      target: ".",
      errors: [],
      findings: findings.map((f, i) => ({ title: f.ruleId ?? `f${i}`, tool: "t", ...f })),
    },
  ];
}

describe("score, verdict and prompts (#273)", () => {
  const root = project({});

  it("scores like argus-scan", () => {
    expect(vibeSummary(result(), root).score).toBe(100);
    const medium = vibeSummary(result({ severity: "moderate", ruleId: "a" }, { severity: "moderate", ruleId: "b" }), root);
    expect([medium.score, medium.verdict]).toEqual([90, "Looks good to launch"]);
    expect(vibeSummary(result({ severity: "critical", ruleId: "k" }), root).score).toBeLessThanOrEqual(39);
    expect(vibeSummary(result({ severity: "critical", ruleId: "k", confidence: "low" }), root).score).toBeGreaterThan(90);
    const repeats = result(...Array.from({ length: 30 }, (_, n) => ({ severity: "high" as const, ruleId: "rls", line: n + 1 })));
    expect(vibeSummary(repeats, root).score).toBe(64);
  });

  it("leaves out noise and files that don't ship", () => {
    const summary = vibeSummary(
      result(
        { severity: "moderate", ruleId: "weak-crypto" },
        { severity: "high", ruleId: "pci-pan-in-source" },
        { severity: "high", ruleId: "vibe-x", context: "test" },
        { severity: "info", ruleId: "note" },
        { severity: "high", ruleId: "vibe-y" },
      ),
      root,
    );
    expect(summary.items.map((i) => i.ruleId)).toEqual(["vibe-y"]);
    expect(summary.notShipped).toBe(1);
  });

  it("prompts never carry secret values", () => {
    const app = project({ ".env": `OPENAI_API_KEY=${OPENAI_KEY}\n`, "a.ts": `const k = "${OPENAI_KEY}"\n` });
    const summary = vibeSummary(
      result({ severity: "high", ruleId: "env", file: ".env", line: 1, fix: "Rotate it." }, { severity: "high", ruleId: "src", file: "a.ts", line: 1 }),
      app,
    );
    for (const item of summary.items) expect(item.prompt).not.toContain(OPENAI_KEY);
    expect(summary.items[0].prompt).toContain("OPENAI_API_KEY=<value hidden>");
    expect(summary.items[0].prompt).toContain("What to change: Rotate it.");
    expect(maskForPrompt("a=sk-ant-api03-abcdefghijklmnopqrstuv b=AIzaSyA1234567890abcdefghijklmnopqrstuv")).not.toMatch(/sk-ant|AIza/);
  });

  it("code excerpts stay inside the project", () => {
    const summary = vibeSummary(result({ severity: "high", ruleId: "x", file: "../../etc/passwd", line: 1 }), root);
    expect(summary.items[0].prompt).not.toContain("Code:");
  });

  it("scan vibe end to end", async () => {
    const app = project({
      ...LOVABLE_APP,
      "app/chat.tsx": `'use client'\nconst openai = new OpenAI({ apiKey: "${OPENAI_KEY}", dangerouslyAllowBrowser: true });\n`,
    });
    const summary = vibeSummary(await runVibeScan(app), app);
    const rules = new Set(summary.items.map((i) => i.ruleId));
    for (const rule of ["vibe-public-env-secret", "vibe-supabase-table-without-rls", "vibe-llm-key-in-browser"]) {
      expect(rules).toContain(rule);
    }
    expect(summary.score).toBeLessThan(40);
    expect(JSON.stringify(summary)).not.toContain(OPENAI_KEY);
  });
});
