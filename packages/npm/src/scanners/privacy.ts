/**
 * `argus-codescan scan pii` and `scan privacy` (#259): the same checks as argus-scan's
 * `argus scan pii` / `argus scan privacy`, with the same rule ids.
 *
 * Argus finds code patterns, not legal compliance.
 */

import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { runNativeSast, sharedRules, type Rule } from "./native-sast.js";
import { downgrade, pathContext } from "./noise.js";
import type { Finding, ScanResult } from "./types.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", "target", ".venv", "venv", "__pycache__"]);
const LOCKFILES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock"]);
const DATA_EXT = new Set([".json", ".yaml", ".yml", ".csv", ".tsv", ".sql", ".xml", ".properties", ".ini", ".toml"]);
const MAX_FILE = 2 * 1024 * 1024;
const PAN_RULE = "pci-pan-in-source";
/** In tests and docs, sample people are the norm: only government ID numbers are reported. */
const REPORT_IN_TESTS = new Set(["pii-hardcoded-ssn", "pii-hardcoded-uk-nino"]);
const KNOWN_TEST_PANS = new Set([
  "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556",
  "5555555555554444", "5105105105105100", "2223003122003222", "378282246310005",
  "371449635398431", "6011111111111117", "6011000990139424",
]);
export const DISCLAIMER = "Code pattern, not a legal assessment: review with whoever owns privacy compliance.";

export function luhnValid(digits: string): boolean {
  if (!/^\d{12,19}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function lineHasRealPan(rule: Rule, line: string): boolean {
  const re = new RegExp(rule.pattern.source, `${rule.pattern.flags.replace("g", "")}g`);
  for (const m of line.matchAll(re)) {
    const digits = m[0].replace(/[ -]/g, "");
    if (!KNOWN_TEST_PANS.has(digits) && luhnValid(digits)) return true;
  }
  return false;
}

function walk(dir: string, out: string[], accept: (name: string) => boolean, depth = 0): void {
  if (depth > 14) return;
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
      st = lstatSync(full);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(full, out, accept, depth + 1);
    else if (accept(name)) out.push(full);
  }
}

function isDataFile(name: string): boolean {
  if (LOCKFILES.has(name)) return false;
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".")).toLowerCase() : "";
  return DATA_EXT.has(ext) || name === ".env" || name.startsWith(".env.");
}

function readLines(file: string, cache: Map<string, string[]>): string[] {
  let lines = cache.get(file);
  if (!lines) {
    try {
      lines = readFileSync(file, "utf8").split("\n");
    } catch {
      lines = [];
    }
    cache.set(file, lines);
  }
  return lines;
}

export async function runPiiScan(target: string): Promise<ScanResult> {
  const rules = sharedRules("pii", "pii-hardcoded", "pci-pan");
  const result = await runNativeSast(target, { rules, tool: "argus-pii" });
  result.errors = result.errors.filter((e) => e !== "No source files found to scan");
  const root = lstatSync(target).isDirectory() ? target : dirname(target);
  const panRule = rules.find((r) => r.id === PAN_RULE);
  const cache = new Map<string, string[]>();
  const seen = new Set<string>();
  let skipped = 0;
  let dropped = 0;

  const keep = (f: Finding, lineText?: string): boolean => {
    const id = f.ruleId ?? "";
    if (id === PAN_RULE) {
      const text = lineText ?? readLines(join(root, f.file ?? ""), cache)[(f.line ?? 1) - 1] ?? "";
      if (f.context === "test" || f.context === "docs" || !panRule || !lineHasRealPan(panRule, text)) {
        dropped++;
        return false;
      }
      return true;
    }
    if (f.context && id.startsWith("pii-hardcoded") && !REPORT_IN_TESTS.has(id)) {
      skipped++;
      return false;
    }
    return true;
  };

  result.findings = result.findings.filter((f) => {
    seen.add(`${f.file}:${f.line}:${f.ruleId}`);
    return keep(f);
  });

  // Data files (fixtures, dumps, config) with the hardcoded-PII and card rules.
  const dataRules = rules.filter((r) => r.id.startsWith("pii-hardcoded") || r.id === PAN_RULE);
  const files: string[] = [];
  if (lstatSync(target).isDirectory()) walk(target, files, isDataFile);
  else if (isDataFile(basename(target))) files.push(target);
  for (const file of files) {
    try {
      if (statSync(file).size > MAX_FILE) continue;
    } catch {
      continue;
    }
    const rel = relative(root, file) || basename(file);
    const context = pathContext(rel);
    const lines = readLines(file, cache);
    lines.forEach((text, i) => {
      for (const rule of dataRules) {
        const key = `${rel}:${i + 1}:${rule.id}`;
        if (seen.has(key) || !rule.pattern.test(text)) continue;
        seen.add(key);
        const finding: Finding = {
          title: rule.title,
          severity: context ? downgrade(rule.severity) : rule.severity,
          tool: "argus-pii",
          file: rel,
          line: i + 1,
          ruleId: rule.id,
          description: "Found in a data file.",
          confidence: rule.confidence ?? "medium",
        };
        if (rule.fix) finding.fix = rule.fix;
        if (context) finding.context = context;
        if (keep(finding, text)) result.findings.push(finding);
      }
    });
  }
  if (skipped) {
    (result.notes ??= []).push(
      `${skipped} name/email/phone/address match(es) in tests and docs not listed (sample data).`,
    );
  }
  void dropped;
  return result;
}

// --- privacy ---------------------------------------------------------------------------------

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?|py|java|kt|php|rb|go|cs|html?|vue|svelte|prisma|json|ya?ml|toml|properties)$/i;
const CONSENT = /cookiebot|onetrust|optanon|osano|klaro|cookieconsent|cookie-consent|vanilla-cookieconsent|usercentrics|iubenda|termly|didomi|consentmanager|cookieyes|complianz|tarteaucitron|react-cookie-consent|@cookie-consent|cookie_consent|cookieConsent|hasConsent|gtag\(\s*['"]consent['"]|ad_storage|analytics_storage|consent_?mode|trackingConsent|posthog\.opt_(?:in|out)_capturing|opt_out_capturing_by_default|optOut\(|mixpanel\.opt_(?:in|out)/i;
const DELETION = /delete_?(?:my_?)?(?:account|user|profile|me)|deleteAccount|deleteUser|removeUser|deleteProfile|close_?account|closeAccount|anonymi[sz]e|pseudonymi[sz]e|erase_?(?:user|data|account)|eraseUser|right_?to_?(?:be_?forgotten|erasure)|gdpr|data_?export|exportData|export_?user|exportUser|download_?(?:my_?)?data|dataPortability|data_?portability|purge_?user|softDelete|soft_delete|@Delete\(\s*['"](?:me|account|profile|users?\/[^'"]*)['"]|(?:router|app|r)\.delete\(\s*['"][^'"]*\/(?:users?|accounts?|profiles?|me)\b/i;
const USER_ROUTE = /(?:@(?:Controller|Get|Post|Put|Patch)\(\s*['"]|(?:app|router|r|fastify)\.(?:get|post|put|patch|use)\(\s*['"])[^'"]*\b(?:users?|accounts?|profiles?|me|members?|customers?|patients?)\b/i;
const PRISMA_MODEL = /^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm;
const PII_FIELD = /^\s*(?:email|phone(?:Number)?|firstName|lastName|fullName|address|dateOfBirth|dob|ssn|nationalId|passport\w*|ipAddress)\s+String/im;
const PERSON_MODEL = /^(?:User|Users|Account|Customer|Client|Member|Person|People|Contact|Lead|Patient|Employee|Student|Applicant|Candidate|Subscriber|Profile|Guest|Visitor|Worker|Staff|Parent|Child)$/i;
const NAME_FIELD = /^\s*name\s+String/m;
const RETENTION_FIELD = /^\s*(?:deleted_?at|deletedAt|expires_?at|expiresAt|expiry|retain_?until|retainUntil|retention\w*|purge_?at|purgeAt|anonymi[sz]ed_?at|anonymi[sz]edAt|ttl|archivedAt|archived_at)\b/im;

function finding(ruleId: string, title: string, severity: Finding["severity"], file: string, line: number, detail: string, fix: string): Finding {
  return {
    title,
    severity,
    tool: "argus-privacy",
    file,
    line,
    ruleId,
    description: `${detail} ${DISCLAIMER}`,
    fix,
    confidence: "low",
  };
}

export async function runPrivacyScan(target: string): Promise<ScanResult> {
  const result = await runNativeSast(target, { rules: sharedRules("privacy-gdpr", "pii"), tool: "argus-privacy" });
  result.errors = result.errors.filter((e) => e !== "No source files found to scan");
  const root = lstatSync(target).isDirectory() ? target : dirname(target);
  const files: string[] = [];
  if (lstatSync(target).isDirectory()) walk(target, files, (n) => SOURCE_EXT.test(n) && !LOCKFILES.has(n));
  else files.push(target);

  let consent: string | undefined;
  let deletion: string | undefined;
  const userRoutes: string[] = [];
  const models: Array<{ name: string; file: string; line: number }> = [];
  for (const file of files) {
    const rel = relative(root, file) || basename(file);
    if (pathContext(rel)) continue;
    let text: string;
    try {
      if (statSync(file).size > MAX_FILE) continue;
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const at = (index: number) => `${rel}:${text.slice(0, index).split("\n").length}`;
    const c = CONSENT.exec(text);
    if (!consent && c) consent = at(c.index);
    const d = DELETION.exec(text);
    if (!deletion && d) deletion = at(d.index);
    const lines = text.split("\n");
    lines.forEach((l, i) => {
      if (USER_ROUTE.test(l)) userRoutes.push(`${rel}:${i + 1}`);
    });
    if (file.endsWith(".prisma")) {
      for (const m of text.matchAll(PRISMA_MODEL)) {
        const body = m[2];
        const personal = PII_FIELD.test(body) || (PERSON_MODEL.test(m[1]) && NAME_FIELD.test(body));
        if (personal && !RETENTION_FIELD.test(body)) {
          models.push({ name: m[1], file: rel, line: text.slice(0, m.index ?? 0).split("\n").length });
        }
      }
    }
  }

  const trackers = result.findings.filter((f) => f.ruleId === "privacy-third-party-tracker");
  for (const f of result.findings) {
    f.description = `${f.description ?? ""} ${DISCLAIMER}`.trim();
    if (f.ruleId === "privacy-third-party-tracker" && consent) {
      f.severity = "info";
      f.description = `A consent mechanism was found (${consent}); check this tracker waits for it. ${DISCLAIMER}`;
    }
  }
  const prodTrackers = trackers.filter((t) => !t.context);
  if (prodTrackers.length && !consent) {
    const first = prodTrackers[0];
    result.findings.push(
      finding(
        "privacy-missing-consent-check",
        `${prodTrackers.length} tracker(s) and no consent mechanism found in the project`,
        "moderate",
        first.file ?? "",
        first.line ?? 0,
        "Analytics and ad trackers need prior consent in the EU/UK (GDPR, ePrivacy) and an opt-out under CCPA. No consent manager or consent-mode call was found anywhere in the code.",
        "Add a consent manager (Cookiebot, OneTrust, Klaro, cookieconsent…) or Google Consent Mode and load trackers only after consent. A banner outside this repository (tag manager, CMS) is fine; then ignore this.",
      ),
    );
  }
  if (userRoutes.length && !deletion) {
    const [file, line] = userRoutes[0].split(/:(?=\d+$)/);
    result.findings.push(
      finding(
        "privacy-no-data-deletion-endpoint",
        "User/account endpoints but no way to delete, anonymise or export a user's data — review",
        "low",
        file,
        Number(line),
        `People can ask for their data to be erased or exported (GDPR Art. 15, 17, 20; CCPA right to delete). Endpoints: ${userRoutes.slice(0, 5).join(", ")}${userRoutes.length > 5 ? ` and ${userRoutes.length - 5} more` : ""}.`,
        "Provide account deletion (or anonymisation) and a data export, in the app or as a documented support process.",
      ),
    );
  }
  for (const m of models.slice(0, 20)) {
    result.findings.push(
      finding(
        "privacy-retention-no-ttl",
        `Model ${m.name} stores personal data with no deletion or expiry field — review retention`,
        "low",
        m.file,
        m.line,
        "Personal data should be deleted or anonymised when it's no longer needed; this model has no deletedAt / expiresAt / retention field.",
        "Decide how long you keep these records, add deletedAt / expiresAt (or a purge job) and document the retention period.",
      ),
    );
  }
  (result.notes ??= []).push(DISCLAIMER);
  return result;
}
