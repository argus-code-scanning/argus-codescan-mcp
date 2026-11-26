#!/usr/bin/env node
/**
 * CLI entry point for argus-codescan.
 *
 * - `scan …`  → native Node.js scans (no Python)
 * - `review`  → native SAST + secrets on Git-changed files
 * - `mcp`     → start Python MCP server (optional, for AI clients)
 * - default   → same as `mcp`
 */

import { spawnPythonMcpServer, checkPythonServerAvailable } from "./python-bridge.js";
import { getMcpServerConfig } from "./config.js";
import { runScanCli } from "./scan-cli.js";
import { runReviewCli } from "./review-cli.js";

const args = process.argv.slice(2);

/** process.exit() drops output still queued for a pipe (`scan … --format json | jq` was cut at 64 KB). */
async function exitAfterFlush(code: number): Promise<never> {
  await new Promise<void>((done) => process.stdout.write("", () => done()));
  process.exit(code);
}

async function main() {
  if (args[0] === "review") {
    await exitAfterFlush(await runReviewCli(args.slice(1)));
  }

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  if (args.includes("--check")) {
    await runCheck();
    process.exit(0);
  }

  if (args.includes("--config")) {
    const method = (args[args.indexOf("--config") + 1] as "pip" | "uvx" | "npx") ?? "uvx";
    const config = getMcpServerConfig(method);
    console.log(JSON.stringify(config.claudeDesktop, null, 2));
    process.exit(0);
  }

  // Native scans — no Python
  if (args[0] === "scan") {
    const code = await runScanCli(args.slice(1));
    await exitAfterFlush(code);
  }

  if (args[0] === "tools") {
    const { runToolsCommand } = await import("./scanners/tools.js");
    const code = await runToolsCommand();
    process.exit(code);
  }

  // Explicit MCP mode or legacy default
  if (args[0] === "mcp" || args.length === 0) {
    await startServer();
    return;
  }

  console.error(`Unknown command: ${args.join(" ")}\n`);
  printHelp();
  process.exit(1);
}

function printHelp() {
  console.log(`
argus-codescan — security scanner for Node.js projects

USAGE:
  argus-codescan scan sca [path]     Dependency vulnerabilities (npm audit)
  argus-codescan scan sast [path]    Source code — Python, Java, PHP, JS, …
  argus-codescan scan secrets [path] Leaked credentials
  argus-codescan scan all [path]     Everything above
  argus-codescan scan pii [path]     Personal data hardcoded in code, config and fixtures
  argus-codescan scan privacy [path] GDPR/CCPA patterns: trackers, consent, deletion, retention
  argus-codescan review [path]       Review changed files (SAST + secrets)
  argus-codescan tools               Show installed scanners
  argus-codescan mcp                 Start MCP server (requires Python)
  argus-codescan --check             Check Python MCP server availability
  argus-codescan --config [method]   Print MCP config JSON (pip|uvx|npx)
  argus-codescan --help              Show this help

NATIVE SCANS (Node.js — no Python):
  scan sca      npm audit (dependencies)
  scan sast     semgrep + eslint (source code, multi-language)
  scan secrets  gitleaks + pattern scan
  scan all      all of the above
  scan pii      hardcoded emails, phones, SSN/NI numbers, names, cards (opt-in)
  scan privacy  trackers without consent, no data deletion, no retention (opt-in)
  tools         list what's installed

INSTALL FOR FULL CODE SCANNING:
  Nothing required — eslint + argus-native are bundled in the npm package.

EXAMPLES:
  argus-codescan scan all .
  argus-codescan scan sast . --fail-on high
  argus-codescan review . --staged --no-csv
  argus-codescan review . --base main --format json
`);
}

async function runCheck() {
  console.log("Checking argus-scan Python server availability...\n");
  const result = await checkPythonServerAvailable();
  if (result.available) {
    console.log("✅ Python MCP server available");
    console.log(`   Command: ${result.command}`);
  } else {
    console.error("❌ Python MCP server not available");
    console.error(`   Error: ${result.error}`);
    console.error("\n   For MCP only: pip install argus-scan");
    console.error("   For npm SCA scans: argus-codescan scan sca . (no Python needed)");
    process.exitCode = 1;
  }
}

async function startServer() {
  const proc = await spawnPythonMcpServer();

  process.stdin.pipe(proc.stdin!);
  proc.stdout!.pipe(process.stdout);
  proc.stderr!.pipe(process.stderr);

  proc.on("exit", (code) => {
    process.exit(code ?? 0);
  });

  process.on("SIGINT", () => proc.kill("SIGINT"));
  process.on("SIGTERM", () => proc.kill("SIGTERM"));
}

main().catch((err) => {
  console.error(`[argus-codescan] Fatal error: ${err.message}`);
  process.exit(1);
});
