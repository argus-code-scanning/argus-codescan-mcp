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
}

export interface ScanResult {
  tool: string;
  scanType: string;
  target: string;
  findings: Finding[];
  errors: string[];
  /** Project directories that were scanned successfully (SCA: one per lockfile). */
  projects?: string[];
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
