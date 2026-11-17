/**
 * .argus.yml for the npm package: `accepted_risks` and `suppressions`, with the same meaning as
 * argus-scan (Python) argus/policy.py.
 *
 *   accepted_risks:
 *     - id: GHSA-fc5q-39xc-vjpf        # advisory, CVE or rule id
 *       package: picomatch             # optional
 *       reason: No patched version; reached via typeorm › tinyglobby
 *       expires: 2026-12-17            # required
 *
 * An accepted risk stays in the report, marked as accepted, and does not fail --fail-on until it
 * expires; after that it counts again with a note. A suppression hides a finding (use sparingly).
 *
 * Only the list-of-maps shape above is read (no YAML library): top-level keys, "- key: value"
 * items and "key: value" continuation lines, quoted or plain, with # comments.
 */

import { existsSync, lstatSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type { Finding, ScanReport } from "./types.js";

export const POLICY_FILENAME = ".argus.yml";
const EXPIRY_WARNING_DAYS = 14;
const ADVISORY_ID =
  /\b(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,}|GO-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|OSV-\d{4}-\d+|MAL-\d{4}-\d+)\b/g;

export interface AcceptedRisk {
  id: string;
  package?: string;
  path?: string;
  reason?: string;
  expires?: string;
}

export interface Suppression {
  rule_id?: string;
  path?: string;
  reason?: string;
  expires?: string;
}

export interface Policy {
  acceptedRisks: AcceptedRisk[];
  suppressions: Suppression[];
}

function scalar(raw: string): string {
  let value = raw.trim();
  if (value.startsWith('"') || value.startsWith("'")) {
    const quote = value[0];
    const end = value.indexOf(quote, 1);
    return end > 0 ? value.slice(1, end) : value.slice(1);
  }
  const comment = value.search(/\s#/);
  if (comment >= 0) value = value.slice(0, comment);
  return value.trim();
}

/** The `accepted_risks` and `suppressions` lists of a .argus.yml file. */
export function parsePolicy(text: string): Policy {
  const lists: Record<string, Record<string, string>[]> = {};
  let section = "";
  let current: Record<string, string> | undefined;
  for (const raw of text.split("\n")) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const top = /^([A-Za-z_][\w-]*):\s*(.*)$/.exec(raw);
    if (top) {
      section = top[1];
      current = undefined;
      if (section === "accepted_risks" || section === "suppressions") lists[section] = [];
      continue;
    }
    if (!lists[section]) continue;
    const item = /^\s*-\s+([\w-]+):\s*(.*)$/.exec(raw);
    if (item) {
      current = { [item[1]]: scalar(item[2]) };
      lists[section].push(current);
      continue;
    }
    const field = /^\s+([\w-]+):\s*(.*)$/.exec(raw);
    if (field && current) current[field[1]] = scalar(field[2]);
  }
  return {
    acceptedRisks: (lists.accepted_risks ?? [])
      .filter((r) => r.id)
      .map((r) => ({ id: r.id, package: r.package, path: r.path, reason: r.reason, expires: r.expires })),
    suppressions: (lists.suppressions ?? []).map((s) => ({ rule_id: s.rule_id, path: s.path, reason: s.reason, expires: s.expires })),
  };
}

/** Walk up from `start` looking for .argus.yml; an explicit path wins. */
export function loadPolicy(start: string, explicit?: string): Policy {
  const empty: Policy = { acceptedRisks: [], suppressions: [] };
  let file = explicit ? resolve(explicit) : undefined;
  if (!file) {
    let dir = resolve(start);
    try {
      if (!lstatSync(dir).isDirectory()) dir = dirname(dir);
    } catch {
      dir = dirname(dir);
    }
    for (;;) {
      if (existsSync(join(dir, POLICY_FILENAME))) {
        file = join(dir, POLICY_FILENAME);
        break;
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  if (!file || !existsSync(file)) return empty;
  try {
    return parsePolicy(readFileSync(file, "utf8"));
  } catch {
    return empty;
  }
}

/** Every advisory / rule id a finding carries (a dependency finding can cover several). */
export function findingIds(f: Finding): Set<string> {
  const ids = new Set<string>([f.ruleId ?? ""]);
  for (const m of `${f.description ?? ""} ${f.url ?? ""} ${f.title}`.matchAll(ADVISORY_ID)) ids.add(m[0]);
  ids.delete("");
  return ids;
}

function globMatch(path: string, pattern: string): boolean {
  const re = new RegExp(
    `^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, ".*")}$`,
  );
  return re.test(path) || re.test(basename(path));
}

function parseDate(value: string | undefined): Date | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return undefined;
  const d = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

function todayUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

function riskMatches(risk: AcceptedRisk, f: Finding): boolean {
  if (!findingIds(f).has(risk.id)) return false;
  if (risk.package && f.package && f.package !== risk.package) return false;
  if (risk.path && !globMatch(f.file ?? "", risk.path)) return false;
  return true;
}

function suppressed(s: Suppression, f: Finding, today: Date): boolean {
  if (s.rule_id && f.ruleId !== s.rule_id && s.rule_id !== f.title && s.rule_id !== f.tool) return false;
  if (s.path && !globMatch(f.file ?? "", s.path)) return false;
  const expiry = parseDate(s.expires);
  return !(expiry && expiry < today);
}

/** Apply suppressions and accepted risks to a report in place; notes go on report.notes. */
export function applyPolicy(report: ScanReport, policy: Policy, today: Date = todayUtc()): ScanReport {
  const notes: string[] = [];
  const active: AcceptedRisk[] = [];
  for (const risk of policy.acceptedRisks) {
    if (parseDate(risk.expires)) active.push(risk);
    else notes.push(`Accepted risk ${risk.id} is ignored: add expires: YYYY-MM-DD (and a reason) so it gets reviewed.`);
  }
  const used = new Set<AcceptedRisk>();
  for (const result of report.results) {
    result.findings = result.findings.filter((f) => !policy.suppressions.some((s) => suppressed(s, f, today)));
    for (const f of result.findings) {
      for (const risk of active) {
        if (!riskMatches(risk, f)) continue;
        used.add(risk);
        if ((parseDate(risk.expires) as Date) < today) {
          f.acceptedRiskExpired = risk.expires;
          continue;
        }
        f.acceptedRisk = { id: risk.id, reason: risk.reason ?? "", expires: risk.expires as string };
        break;
      }
    }
  }
  for (const risk of active) {
    const expiry = parseDate(risk.expires) as Date;
    const why = risk.reason ? ` (${risk.reason})` : "";
    const days = Math.round((expiry.getTime() - today.getTime()) / 86_400_000);
    if (!used.has(risk)) {
      notes.push(`Accepted risk ${risk.id} matched no finding: it may be fixed; remove it from .argus.yml.`);
    } else if (days < 0) {
      notes.push(`Accepted risk ${risk.id} expired on ${risk.expires} and counts again${why}. Fix it or review it and set a new expiry date.`);
    } else if (days <= EXPIRY_WARNING_DAYS) {
      notes.push(`Accepted risk ${risk.id} expires in ${days} day${days === 1 ? "" : "s"} (${risk.expires})${why}.`);
    }
  }
  if (notes.length) report.notes = notes;
  return report;
}
