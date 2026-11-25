import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast, sharedRules } from "../src/scanners/native-sast.js";
import { luhnValid, runPiiScan, runPrivacyScan } from "../src/scanners/privacy.js";

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "argus-shared-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}
const ids = (r: { findings: { ruleId?: string }[] }) => new Set(r.findings.map((f) => f.ruleId));

describe("generated shared rules", () => {
  it("are up to date with the argus-languages YAML packs", () => {
    expect(() => execFileSync("node", ["scripts/sync-shared-rules.mjs", "--check"], { stdio: "pipe" })).not.toThrow();
  });

  it("compile and keep argus-scan's rule ids", () => {
    const all = sharedRules("cookies", "pii", "pii-hardcoded", "pci-pan", "privacy-gdpr");
    expect(all.length).toBeGreaterThan(25);
    expect(all.map((r) => r.id)).toEqual(
      expect.arrayContaining(["js-cookie-sensitive-no-options", "pii-email-in-logs", "pii-hardcoded-ssn", "pci-pan-in-source", "privacy-third-party-tracker"]),
    );
  });

  // Same cases as argus-languages tests/test_pii_hardcoded_rules.py.
  const hard = sharedRules("pii-hardcoded");
  const hits = (line: string) => new Set(hard.filter((r) => r.pattern.test(line)).map((r) => r.id));
  it.each([
    ['email = "maria.gonzalez@gmail.com"', "pii-hardcoded-email"],
    ['"phoneNumber": "(415) 867-2309"', "pii-hardcoded-phone"],
    ['ssn = "219-09-9999"', "pii-hardcoded-ssn"],
    ["national_insurance = 'JG 10 32 87 B'", "pii-hardcoded-uk-nino"],
    ['"fullName": "Oluwaseun Adebayo"', "pii-hardcoded-name"],
    ["ADMIN_EMAIL='olu.adebayo@gmail.com'", "pii-hardcoded-email"],
  ])("flags %s", (line, rule) => expect(hits(line)).toContain(rule));
  it.each([
    'email = "jane.doe@example.com"',
    'email = "support@acme.com"',
    'phone = "+1 202-555-0123"',
    'ssn = "123-45-6789"',
    'first_name = "John"',
    "firstName: 'Deleted',",
    "@ApiPropertyOptional({ example: '14 Harehills Lane, Leeds LS9 7EW' })",
  ])("ignores %s", (line) => expect(hits(line)).toEqual(new Set()));
});

describe("default scan includes cookie and PII-in-logs rules", () => {
  it("flags them in argus-native", async () => {
    const dir = project({
      "server.js": 'res.cookie("session", token);\nlogger.info(`login ${user.email}`);\n',
      "index.html": '<script>eval(x)</script>\n',  // templates only get rules written for them
    });
    const found = ids(await runNativeSast(dir));
    expect(found).toContain("js-cookie-sensitive-no-options");
    expect(found).toContain("pii-email-in-logs");
    expect(found).not.toContain("injection-eval");
  });
});

describe("scan pii", () => {
  it("finds code and data-file PII, Luhn-checks cards, skips sample data in tests", async () => {
    const dir = project({
      "app.py": 'CONTACT = {"email": "maria.gonzalez@gmail.com", "ssn": "219-09-9999"}\n',
      "data/customers.json": '[{"first_name": "Margaret", "phone": "+44 7700 912345"}]\n',
      "exports/payments.csv": "name,card\nMargaret,4539 1488 0343 6467\nsample,4111 1111 1111 1111\n",
      ".env": "ADMIN_EMAIL='olu.adebayo@gmail.com'\n",
      "package-lock.json": '{"email": "maintainer@gmail.com"}\n',
      "tests/data.yaml": 'ssn: "219-09-9999"\nfirst_name: "Margaret"\n',
    });
    const r = await runPiiScan(dir);
    const at = new Set(r.findings.map((f) => `${f.file}:${f.ruleId}`));
    expect(at).toContain("app.py:pii-hardcoded-email");
    expect(at).toContain("app.py:pii-hardcoded-ssn");
    expect(at).toContain("data/customers.json:pii-hardcoded-name");
    expect(at).toContain("data/customers.json:pii-hardcoded-phone");
    expect(at).toContain("exports/payments.csv:pci-pan-in-source");
    expect(at).toContain(".env:pii-hardcoded-email");
    expect(at).toContain("tests/data.yaml:pii-hardcoded-ssn");
    expect(at).not.toContain("tests/data.yaml:pii-hardcoded-name");
    expect([...at].some((k) => k.startsWith("package-lock.json"))).toBe(false);
    expect(r.findings.filter((f) => f.ruleId === "pci-pan-in-source")).toHaveLength(1);
    expect(r.findings.find((f) => f.file === "tests/data.yaml")?.severity).toBe("moderate");
  });

  it("luhn", () => {
    expect(luhnValid("4539148803436467")).toBe(true);
    expect(luhnValid("4539148803436468")).toBe(false);
  });
});

describe("scan privacy", () => {
  const GA = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>\n';
  it("trackers without consent", async () => {
    const found = ids(await runPrivacyScan(project({ "public/index.html": GA })));
    expect(found).toContain("privacy-third-party-tracker");
    expect(found).toContain("privacy-missing-consent-check");
  });
  it("consent turns trackers into notes", async () => {
    const r = await runPrivacyScan(project({ "public/index.html": GA, "src/c.js": "gtag('consent', 'default', {});\n" }));
    expect(ids(r)).not.toContain("privacy-missing-consent-check");
    expect(r.findings.find((f) => f.ruleId === "privacy-third-party-tracker")?.severity).toBe("info");
  });
  it("user endpoints without deletion, and retention", async () => {
    const dir = project({
      "src/users.ts": "@Controller('users')\nexport class U {}\n",
      "prisma/schema.prisma": "model User {\n  id String @id\n  email String\n}\n\nmodel Session {\n  id String @id\n  expiresAt DateTime\n}\n\nmodel Organization {\n  id String @id\n  name String\n}\n",
    });
    const r = await runPrivacyScan(dir);
    expect(ids(r)).toContain("privacy-no-data-deletion-endpoint");
    expect(r.findings.filter((f) => f.ruleId === "privacy-retention-no-ttl").map((f) => f.title.split(" ")[1])).toEqual(["User"]);
  });
  it("deleting an API key isn't deleting a user", async () => {
    const dir = project({
      "src/users.ts": "@Controller('users')\nexport class U {}\n",
      "src/keys.ts": "@Delete(':id')\nremove() {}\n",
    });
    expect(ids(await runPrivacyScan(dir))).toContain("privacy-no-data-deletion-endpoint");
  });
});
