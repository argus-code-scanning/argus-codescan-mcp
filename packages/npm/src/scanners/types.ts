export type Severity = "critical" | "high" | "moderate" | "low" | "info";

export interface Finding {
  title: string;
  severity: Severity;
  tool: string;
  file?: string;
  line?: number;
  package?: string;
  version?: string;
  description?: string;
  url?: string;
  ruleId?: string;
  /** Built-in rules: how likely a match is a real issue. Low does not fail --fail-on by default. */
  confidence?: Confidence;
  /** Set when the file probably does not ship; the severity was lowered one level. */
  context?: FindingContext;
}

export type Confidence = "high" | "medium" | "low";
export type FindingContext = "test" | "docs" | "generated";

export interface ScanResult {
  tool: string;
  scanType: string;
  target: string;
  findings: Finding[];
  errors: string[];
  /** Project directories that were scanned successfully (SCA: one per lockfile). */
  projects?: string[];
  /** Findings silenced by argus-ignore comments (with their reasons). */
  suppressed?: { ruleId: string; file: string; line: number; reason: string }[];
}

export interface ScanReport {
  target: string;
  scanType: string;
  results: ScanResult[];
  summary: {
    total: number;
    critical: number;
    high: number;
    moderate: number;
    low: number;
    info: number;
  };
}
