import type { Severity } from "./types.js";

export function mapSemgrepSeverity(value: string | undefined): Severity {
  const s = (value ?? "WARNING").toUpperCase();
  if (s === "ERROR") return "high";
  if (s === "WARNING") return "moderate";
  if (s === "INFO") return "low";
  return "moderate";
}

export function mapGitleaksSeverity(_ruleId: string): Severity {
  return "high";
}

export function mapEslintSeverity(severity: number): Severity {
  if (severity === 2) return "high";
  if (severity === 1) return "moderate";
  return "low";
}

const FAIL_ON_VALUES = ["critical", "high", "moderate", "low", "info", "never"] as const;

/**
 * --fail-on value. "medium" (the word argus-scan, the docs and the GitHub Action use) means
 * "moderate". Anything else unknown is an error: an unrecognised threshold used to fail nothing,
 * so a typo silently passed every build.
 */
export function parseFailOn(value: string): Severity | "never" {
  const v = value.trim().toLowerCase();
  const normalized = v === "medium" ? "moderate" : v;
  if (!(FAIL_ON_VALUES as readonly string[]).includes(normalized)) {
    throw new Error(
      `Invalid --fail-on value: ${value} (use critical, high, medium, low, info or never)`,
    );
  }
  return normalized as Severity | "never";
}
