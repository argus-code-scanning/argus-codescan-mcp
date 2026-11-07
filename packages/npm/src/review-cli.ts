import { resolve } from "node:path";
import { runReview } from "./review.js";
import { printScanReport } from "./scanners/report.js";
import type { Severity } from "./scanners/types.js";

export function printReviewHelp(): void {
  console.log(`
argus-codescan review — SAST and secrets for Git-changed files

USAGE:
  argus-codescan review [path] [--staged | --base REF]

OPTIONS:
  --staged                   Scan staged contents from the Git index
  --base REF                 Compare REF...HEAD, plus dirty and untracked files
  --format json|table|csv     Console output (default: table)
  --output, -o FILE           CSV report path
  --no-csv                    Skip writing CSV file
  --fail-on critical|high|moderate|low|info|never
  --fail-on-low-confidence   Let low-confidence rule matches trigger --fail-on too

The path locates the repository; review covers its changed files.
Without --staged or --base, review compares the working tree with HEAD
and includes untracked files. Deleted files and symlinks are skipped.
This scans whole changed files, not only changed lines.
For malware scanning and full tool coverage, use argus review (Python).
`);
}

/** Parse review options and print a report using the existing scan output formats. */
export async function runReviewCli(args: string[]): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) { printReviewHelp(); return 0; }
  let target = ".";
  let hasTarget = false;
  let staged = false;
  let base: string | undefined;
  let format: "json" | "table" | "csv" = "table";
  let failOn: Severity | "never" = "never";
  let csvPath: string | undefined;
  let writeCsv = true;
  let includeLowConfidence = false;
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === "--staged") { staged = true; continue; }
      if (arg === "--no-csv") { writeCsv = false; continue; }
      if (arg === "--fail-on-low-confidence") { includeLowConfidence = true; continue; }
      if (["--base", "--format", "--fail-on", "--output", "-o"].includes(arg)) {
        const value = args[++i];
        if (!value || value.startsWith("-")) throw new Error(`Missing value for ${arg}.`);
        if (arg === "--base") base = value;
        else if (arg === "--output" || arg === "-o") csvPath = resolve(value);
        else if (arg === "--format") {
          if (!["json", "table", "csv"].includes(value)) throw new Error(`Invalid format: ${value}`);
          format = value as typeof format;
        } else {
          if (!["critical", "high", "moderate", "low", "info", "never"].includes(value)) {
            throw new Error(`Invalid severity: ${value}`);
          }
          failOn = value as typeof failOn;
        }
      } else if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
      else if (hasTarget) throw new Error("Only one review path is supported.");
      else { target = arg; hasTarget = true; }
    }
    const { report, files } = await runReview(target, { staged, base });
    console.error(`Changed files scanned: ${files.length}`);
    if (files.length === 0) console.error("No changed files to review.");
    return printScanReport(report, format, failOn, { csvPath, writeCsv, includeLowConfidence });
  } catch (err) {
    console.error(`Review failed: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}
