import { resolve } from "node:path";
import { buildReport, printScanReport } from "./scanners/report.js";
import { runAllSast } from "./scanners/sast.js";
import { runNpmAuditSca } from "./scanners/sca.js";
import { runAllSecrets } from "./scanners/secrets.js";
import { runToolsCommand } from "./scanners/tools.js";
import type { Severity } from "./scanners/types.js";

function printScanHelp(): void {
  console.log(`
argus-codescan scan — Windows, macOS, Linux (no brew, no Python)

USAGE:
  argus-codescan scan sca [path]       npm dependencies
  argus-codescan scan sast [path]      Source code (built-in scanners)
  argus-codescan scan secrets [path]   Credentials / API keys
  argus-codescan scan all [path]       Everything
  argus-codescan tools                 What's bundled

BUILT-IN (ships with npm install):
  argus-native     Python, Java, PHP, JS, TS, Go — injection, XSS, SQLi, …
  eslint-security  JavaScript / JSX security rules
  argus-secrets    Pattern-based secret detection

OPTIONS:
  --format json|table|csv     Console output (default: table)
  --output, -o FILE           CSV file path (default: argus-<type>-<timestamp>.csv in cwd)
  --no-csv                    Skip writing CSV file
  --fail-on critical|high|moderate

EXAMPLES:
  argus-codescan scan all .
  argus-codescan scan sast . --fail-on high
  argus-codescan scan sca . --output ./reports/deps.csv
`);
}

function parseScanArgs(args: string[]): {
  format: "json" | "table" | "csv";
  failOn: Severity | "never";
  target: string;
  csvPath?: string;
  writeCsv: boolean;
} {
  let format: "json" | "table" | "csv" = "table";
  let failOn: Severity | "never" = "never";
  let csvPath: string | undefined;
  let writeCsv = true;
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--format" && args[i + 1]) {
      format = args[++i] as "json" | "table" | "csv";
    } else if ((arg === "--output" || arg === "-o") && args[i + 1]) {
      csvPath = resolve(args[++i]);
    } else if (arg === "--no-csv") {
      writeCsv = false;
    } else if (arg === "--fail-on" && args[i + 1]) {
      failOn = args[++i] as Severity | "never";
    } else if (!arg.startsWith("-")) {
      positional.push(arg);
    }
  }

  return { format, failOn, target: resolve(positional[0] ?? "."), csvPath, writeCsv };
}

export async function runScanCli(args: string[]): Promise<number> {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    printScanHelp();
    return 0;
  }

  if (args[0] === "tools") {
    return runToolsCommand();
  }

  const scanType = args[0];
  const { format, failOn, target, csvPath, writeCsv } = parseScanArgs(args.slice(1));
  const reportOpts = { csvPath, writeCsv };

  if (scanType === "sca") {
    console.error(`Running SCA scan (npm audit) on: ${target}`);
    const scaResult = await runNpmAuditSca(target);
    if (scaResult.errors.length > 0 && scaResult.findings.length === 0) {
      for (const err of scaResult.errors) console.error(`Error: ${err}`);
      return 1;
    }
    return printScanReport(buildReport(target, "sca", [scaResult]), format, failOn, reportOpts);
  }

  if (scanType === "sast") {
    console.error(`Running SAST scan (source code) on: ${target}`);
    console.error("  Built-in: argus-native + eslint-security + opengrep (auto, no pip)\n");
    const results = await runAllSast(target);
    return printScanReport(buildReport(target, "sast", results), format, failOn, reportOpts);
  }

  if (scanType === "secrets") {
    console.error(`Running secrets scan on: ${target}`);
    const results = await runAllSecrets(target);
    return printScanReport(buildReport(target, "secrets", results), format, failOn, reportOpts);
  }

  if (scanType === "all") {
    console.error(`Running full scan on: ${target}`);
    console.error("  sca + sast (built-in) + secrets\n");
    const [sca, sastResults, secretResults] = await Promise.all([
      runNpmAuditSca(target),
      runAllSast(target),
      runAllSecrets(target),
    ]);
    const results = [sca, ...sastResults, ...secretResults];
    return printScanReport(buildReport(target, "all", results), format, failOn, reportOpts);
  }

  console.error(`Unknown scan type: ${scanType}`);
  printScanHelp();
  return 1;
}

export { runToolsCommand };
