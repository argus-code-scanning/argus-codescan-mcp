/**
 * Bridge to locate and invoke the Python Argus MCP server.
 *
 * Resolution order:
 *  1. ARGUS_MCP_PYTHON env var (explicit override)
 *  2. `argus-mcp` on PATH
 *  3. `argus mcp` on PATH
 *  4. `uvx --from argus-scan argus-mcp` (or `argus mcp`)
 *  5. `python -m argus.server`
 */

import which from "which";
import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";

export interface PythonServerOptions {
  pythonPath?: string;
  mcpCommandPath?: string;
  env?: Record<string, string>;
}

async function findOnPath(candidates: string[]): Promise<string | null> {
  for (const name of candidates) {
    try {
      return await which(name);
    } catch {
      // try next
    }
  }
  return null;
}

async function findPython(): Promise<string | null> {
  return findOnPath(["python3", "python"]);
}

/**
 * Resolve the command to launch the Python MCP server.
 */
export async function resolvePythonMcpCommand(
  opts: PythonServerOptions = {},
): Promise<{ command: string; args: string[] }> {
  const envCommand = process.env.ARGUS_MCP_PYTHON ?? process.env.CODETESTING_MCP_PYTHON;
  if (envCommand) {
    return { command: envCommand, args: [] };
  }

  if (opts.mcpCommandPath) {
    return { command: opts.mcpCommandPath, args: [] };
  }

  const argusMcp = await findOnPath(["argus-mcp"]);
  if (argusMcp) {
    return { command: argusMcp, args: [] };
  }

  const argusCli = await findOnPath(["argus", "argus-scan"]);
  if (argusCli) {
    return { command: argusCli, args: ["mcp"] };
  }

  try {
    await which("uvx");
    // PyPI package exposes `argus` and `argus-mcp`, not `argus-scan` as uvx executable name
    return { command: "uvx", args: ["--from", "argus-scan", "argus-mcp"] };
  } catch {
    // not found
  }

  const pythonExecutable = opts.pythonPath || (await findPython());
  if (pythonExecutable) {
    return {
      command: pythonExecutable,
      args: ["-m", "argus.server"],
    };
  }

  throw new Error(
    "Could not find Argus MCP server. Install with:\n" +
      "  pip install argus-scan\n" +
      "  OR for npm-only SCA scans (no Python):\n" +
      "  argus-codescan scan sca .",
  );
}

export async function spawnPythonMcpServer(
  opts: PythonServerOptions = {},
): Promise<ChildProcess> {
  const { command, args } = await resolvePythonMcpCommand(opts);

  const proc = spawn(command, args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ...opts.env },
  });

  proc.on("error", (err) => {
    console.error(`[argus-codescan] MCP server error: ${err.message}`);
  });

  return proc;
}

export async function checkPythonServerAvailable(
  opts: PythonServerOptions = {},
): Promise<{ available: boolean; command?: string; error?: string }> {
  try {
    const { command, args } = await resolvePythonMcpCommand(opts);
    return { available: true, command: [command, ...args].join(" ") };
  } catch (err) {
    return {
      available: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
