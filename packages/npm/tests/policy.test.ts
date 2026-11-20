/** .argus.yml accepted risks and suppressions, same behaviour as argus-scan tests/test_accepted_risks.py. */
import { describe, expect, it } from "vitest";
import { applyPolicy, findingIds, parsePolicy } from "../src/scanners/policy.js";
import { buildReport, countFailing } from "../src/scanners/report.js";
import type { Finding } from "../src/scanners/types.js";

const TODAY = new Date(Date.UTC(2026, 10, 17));
const day = (offset: number) => new Date(TODAY.getTime() + offset * 86_400_000).toISOString().slice(0, 10);

const picomatch = (): Finding => ({
  title: "picomatch vulnerable to ReDoS",
  severity: "high",
  tool: "npm-audit",
  file: "package-lock.json",
  package: "picomatch",
  ruleId: "GHSA-fc5q-39xc-vjpf",
});
const lodash = (): Finding => ({ title: "lodash", severity: "high", tool: "npm-audit", ruleId: "GHSA-35jh-r3h4-6jhm" });
const grouped = (): Finding => ({
  title: "nokogiri: 3 known vulnerabilities",
  severity: "critical",
  tool: "osv-deps",
  package: "nokogiri",
  ruleId: "GHSA-353f-x4gh-cqq8",
  description: "[runtime dependency] Ruby package nokogiri 1.13.0: GHSA-353f-x4gh-cqq8, GHSA-59gp-qqm7-cw4j, GHSA-c4rq-3m3g-8wgx",
});
const report = (...findings: Finding[]) =>
  buildReport(".", "sca", [{ tool: "npm-audit", scanType: "sca", target: ".", findings, errors: [] }]);

describe(".argus.yml accepted risks", () => {
  it("reads the accepted_risks and suppressions lists", () => {
    const policy = parsePolicy(`# policy
fail_on: high
accepted_risks:
  - id: GHSA-fc5q-39xc-vjpf   # picomatch
    package: picomatch
    reason: "No patched version; via typeorm > tinyglobby"
    expires: 2026-12-17
suppressions:
  - rule_id: bandit.B101
    path: "tests/**"
`);
    expect(policy.acceptedRisks).toEqual([
      { id: "GHSA-fc5q-39xc-vjpf", package: "picomatch", path: undefined, reason: "No patched version; via typeorm > tinyglobby", expires: "2026-12-17" },
    ]);
    expect(policy.suppressions).toEqual([{ rule_id: "bandit.B101", path: "tests/**", reason: undefined, expires: undefined }]);
  });

  it("keeps an accepted finding visible but out of --fail-on", () => {
    const r = applyPolicy(report(picomatch(), lodash()), parsePolicy(`accepted_risks:\n  - id: GHSA-fc5q-39xc-vjpf\n    reason: no fix yet\n    expires: ${day(30)}\n`), TODAY);
    expect(r.results[0].findings).toHaveLength(2);
    expect(r.results[0].findings[0].acceptedRisk).toEqual({ id: "GHSA-fc5q-39xc-vjpf", reason: "no fix yet", expires: day(30) });
    expect(countFailing(r, "high")).toBe(1);
    expect(r.notes).toBeUndefined();
  });

  it("counts an expired risk again, with a note", () => {
    const r = applyPolicy(report(picomatch()), parsePolicy(`accepted_risks:\n  - id: GHSA-fc5q-39xc-vjpf\n    reason: no fix yet\n    expires: ${day(-1)}\n`), TODAY);
    expect(r.results[0].findings[0].acceptedRisk).toBeUndefined();
    expect(r.results[0].findings[0].acceptedRiskExpired).toBe(day(-1));
    expect(countFailing(r, "high")).toBe(1);
    expect(r.notes?.[0]).toMatch(/^Accepted risk GHSA-fc5q-39xc-vjpf expired on .* and counts again \(no fix yet\)/);
  });

  it("matches any advisory in a grouped finding, and respects package", () => {
    expect(findingIds(grouped()).has("GHSA-59gp-qqm7-cw4j")).toBe(true);
    const ok = applyPolicy(report(grouped()), parsePolicy(`accepted_risks:\n  - id: GHSA-59gp-qqm7-cw4j\n    expires: ${day(60)}\n`), TODAY);
    expect(ok.results[0].findings[0].acceptedRisk?.id).toBe("GHSA-59gp-qqm7-cw4j");
    const other = applyPolicy(report(picomatch()), parsePolicy(`accepted_risks:\n  - id: GHSA-fc5q-39xc-vjpf\n    package: micromatch\n    expires: ${day(60)}\n`), TODAY);
    expect(other.results[0].findings[0].acceptedRisk).toBeUndefined();
  });

  it("notes a missing expiry, an unused entry and an expiry within 14 days", () => {
    const r = applyPolicy(
      report(picomatch(), lodash()),
      parsePolicy(`accepted_risks:
  - id: GHSA-fc5q-39xc-vjpf
    reason: no fix yet
    expires: ${day(3)}
  - id: GHSA-35jh-r3h4-6jhm
  - id: GHSA-xxxx-xxxx-xxxx
    expires: ${day(90)}
`),
      TODAY,
    );
    expect(r.notes).toEqual([
      "Accepted risk GHSA-35jh-r3h4-6jhm is ignored: add expires: YYYY-MM-DD (and a reason) so it gets reviewed.",
      `Accepted risk GHSA-fc5q-39xc-vjpf expires in 3 days (${day(3)}) (no fix yet).`,
      "Accepted risk GHSA-xxxx-xxxx-xxxx matched no finding: it may be fixed; remove it from .argus.yml.",
    ]);
    expect(r.results[0].findings[1].acceptedRisk).toBeUndefined();
  });

  it("suppressions hide findings until they expire", () => {
    const r = applyPolicy(report(picomatch(), lodash()), parsePolicy(`suppressions:\n  - rule_id: GHSA-35jh-r3h4-6jhm\n    expires: ${day(10)}\n`), TODAY);
    expect(r.results[0].findings.map((f) => f.package ?? f.title)).toEqual(["picomatch"]);
    const expired = applyPolicy(report(lodash()), parsePolicy(`suppressions:\n  - rule_id: GHSA-35jh-r3h4-6jhm\n    expires: ${day(-10)}\n`), TODAY);
    expect(expired.results[0].findings).toHaveLength(1);
  });
});
