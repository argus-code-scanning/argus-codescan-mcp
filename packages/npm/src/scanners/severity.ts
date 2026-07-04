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
