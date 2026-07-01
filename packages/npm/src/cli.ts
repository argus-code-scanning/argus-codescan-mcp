#!/usr/bin/env node
/**
 * CLI entry point for the argus-scan npm package.
 *
 * When invoked, it locates and starts the Python MCP server,
 * piping stdio through so MCP clients can communicate with it.
 */

import { spawnPythonMcpServer, checkPythonServerAvailable } from "./python-bridge.js";
import { getMcpServerConfig } from "./config.js";

const args = process.argv.slice(2);

async function main() {
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

  // Default: start the MCP server
  await startServer();
}

function printHelp() {
  console.log(`
argus-scan — MCP server for code security testing

USAGE:
  argus-scan [options]

OPTIONS:
  (no args)         Start the MCP server (stdio transport)
  --check           Check if the Python server is available
  --config [method] Print MCP config JSON (method: pip|uvx|npx)
  --help, -h        Show this help

SETUP:
  Add to your MCP client config (e.g. ~/.cursor/mcp.json):
  
  {
    "mcpServers": {
      "argus-scan": {
        "command": "npx",
        "args": ["-y", "argus-scan"]
      }
    }
  }

  Or with uvx (recommended):
  {
    "mcpServers": {
      "argus-scan": {
        "command": "uvx",
        "args": ["argus-scan"]
      }
    }
  }

TOOLS PROVIDED:
  scan_sast        Static code analysis (Semgrep, Bandit, ESLint)
  scan_dast        Dynamic web app scanning (OWASP ZAP, Nikto)
  scan_sca         Dependency scanning (Trivy, Safety, pip-audit, npm audit)
  scan_secrets     Secret/credential detection (Gitleaks, detect-secrets, TruffleHog)
  scan_iac         IaC misconfiguration (Checkov, Trivy, Terrascan)
  scan_container   Container image scanning (Trivy)
  scan_all         Full comprehensive scan
  check_tools      List available scanning tools
`);
}

async function runCheck() {
  console.log("Checking argus-scan Python server availability...\n");
  const result = await checkPythonServerAvailable();
  if (result.available) {
    console.log(`✅ Python MCP server available`);
    console.log(`   Command: ${result.command}`);
  } else {
    console.error(`❌ Python MCP server not available`);
    console.error(`   Error: ${result.error}`);
    console.error(`\n   Install with: pip install argus-scan`);
    process.exitCode = 1;
  }
}

async function startServer() {
  const proc = await spawnPythonMcpServer();

  // Pipe stdio through to the parent process (MCP protocol)
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
  console.error(`[argus-scan] Fatal error: ${err.message}`);
  process.exit(1);
});
