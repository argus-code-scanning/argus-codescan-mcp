/**
 * Shared type definitions matching the Python models.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type ScanType = "sast" | "dast" | "sca" | "secrets" | "iac" | "container";

export interface Finding {
  title: string;
  severity: Severity;
  scan_type: ScanType;
  tool: string;
  file: string;
  line: number;
  column: number;
  description: string;
  cwe: string;
  cve: string;
  fix_guidance: string;
  rule_id: string;
  references: string[];
}

export interface ScanResultSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
}

export interface ScanResult {
  tool: string;
  scan_type: ScanType;
  target: string;
  tool_available: boolean;
  summary: ScanResultSummary;
  findings: Finding[];
  errors: string[];
  metadata: Record<string, unknown>;
}

export interface AggregatedSummary {
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_scan_type: Record<ScanType, number>;
  by_tool: Record<string, number>;
  tools_run: string[];
  tools_unavailable: string[];
}

export interface AggregatedReport {
  target: string;
  summary: AggregatedSummary;
  results: ScanResult[];
}

export interface ScanOptions {
  target?: string;
  targetUrl?: string;
  containerImage?: string;
  tools?: string[];
  semgrepConfig?: string;
  timeout?: number;
  format?: "markdown" | "json";
}
