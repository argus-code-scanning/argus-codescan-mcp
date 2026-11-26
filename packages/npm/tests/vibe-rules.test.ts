import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

// Same cases as argus-languages tests/test_vibe_rules.py (#272).
const SERVICE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ";

async function vibe(name: string, code: string): Promise<Array<[string, number]>> {
  const dir = mkdtempSync(join(tmpdir(), "argus-vibe-"));
  writeFileSync(join(dir, name), `${code}\n`);
  return (await runNativeSast(dir)).findings
    .filter((f) => (f.ruleId ?? "").startsWith("vibe-"))
    .map((f) => [f.ruleId ?? "", f.line ?? 0]);
}

describe("rules for AI-built apps (#272)", () => {
  it.each([
    ["page.tsx", "const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;", "vibe-public-env-secret"],
    ["chat.ts", "new OpenAI({ apiKey, dangerouslyAllowBrowser: true });", "vibe-llm-key-in-browser"],
    ["db.ts", `createClient(url, "${SERVICE_KEY}")`, "vibe-supabase-service-role-key"],
    ["001.sql", 'create policy "w" on public.notes\n  for insert\n  with check (true);', "vibe-supabase-policy-allows-all"],
    ["002.sql", 'create policy "r" on public.orders for select to authenticated using (true);', "vibe-supabase-policy-reads-all"],
    ["003.sql", "alter table public.orders disable row level security;", "vibe-supabase-rls-disabled"],
  ])("%s: flags %s", async (name, code, rule) => {
    expect((await vibe(name, code)).map(([id]) => id)).toContain(rule);
  });

  it.each([
    ["page.tsx", "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;"],
    ["001.sql", 'create policy "r" on public.products for select using (true);'],
    ["002.sql", "-- alter table public.orders disable row level security;"],
    ["003.sql", 'create policy "svc" on public.jobs for all to service_role using (true);'],
  ])("%s: ignores %s", async (name, code) => {
    expect(await vibe(name, code)).toEqual([]);
  });

  it("reports a multi-line policy on the line it starts", async () => {
    expect(await vibe("m.sql", 'select 1;\ncreate policy "w" on public.notes\n  for update\n  using (true);')).toEqual([
      ["vibe-supabase-policy-allows-all", 2],
    ]);
  });

  it("a leaked service_role key can't be silenced with an ignore comment", async () => {
    const found = await vibe("db.ts", `// argus-ignore vibe-supabase-service-role-key: test\nconst k = "${SERVICE_KEY}";`);
    expect(found).toEqual([["vibe-supabase-service-role-key", 2]]);
  });

  it("SQL files only get rules written for SQL", async () => {
    expect(await vibe("seed.sql", "insert into t values ('NEXT_PUBLIC_OPENAI_API_KEY');")).toEqual([]);
  });
});
