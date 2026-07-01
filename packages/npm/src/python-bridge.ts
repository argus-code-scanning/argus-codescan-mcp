/**
 * Bridge to locate and invoke the Python argus-scan server.
 *
 * Resolution order:
 *  1. CODETESTING_MCP_PYTHON env var (explicit override)
 *  2. `argus-scan` CLI on PATH (pip-installed)
 *  3. `uvx argus-scan` (uv tool runner — no install needed)
 *  4. `python -m argus.server` (if argus importable)
 */

import which from "which";
import { execaNode, execa } from "execa";
import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";

export interface PythonServerOptions {
  /** Override the Python executable */
  pythonPath?: string;
  /** Override the argus-scan CLI path */
  mcpCommandPath?: string;
  /** Extra environment variables */
  env?: Record<string, string>;
}

/**
 * Resolve the command to launch the Python MCP server.
 * Returns [command, args] or throws if no viable option is found.
 */
export async function resolvePythonMcpCommand(
  opts: PythonServerOptions = {}
): Promise<{ command: string; args: string[] }> {
  // 1. Explicit env override
  const envCommand = process.env.CODETESTING_MCP_PYTHON;
  if (envCommand) {
    return { command: envCommand, args: [] };
  }

  // 2. Explicit option override
  if (opts.mcpCommandPath) {
    return { command: opts.mcpCommandPath, args: [] };
  }

  // 3. argus-scan CLI on PATH
  try {
    const cliPath = await which("argus-scan");
    return { command: cliPath, args: [] };
  } catch {
    // not found
  }

  // 4. uvx (no install needed)
  try {
    await which("uvx");
    return { command: "uvx", args: ["argus-scan"] };
  } catch {
    // not found
  }

  // 5. python -m argus.server
  const pythonExecutable = opts.pythonPath || (await findPython());
  if (pythonExecutable) {
    return {
      command: pythonExecutable,
      args: ["-m", "argus.server"],
    };
  }

  throw new Error(
    "Could not find argus-scan. Install with:\n" +
      "  pip install argus-scan\n" +
      "  OR\n" +
      "  Set CODETESTING_MCP_PYTHON environment variable"
  );
}

async function findPython(): Promise<string | null> {
  for (const candidate of ["python3", "python"]) {
    try {
      return await which(candidate);
    } catch {
      // try next
    }
  }
  return null;
}

/**
 * Spawn the Python MCP server process and return it.
 * The process communicates via stdio (MCP protocol).
 */
export async function spawnPythonMcpServer(
  opts: PythonServerOptions = {}
): Promise<ChildProcess> {
  const { command, args } = await resolvePythonMcpCommand(opts);

  const proc = spawn(command, args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, ...opts.env },
  });

  proc.on("error", (err) => {
    console.error(`[argus-scan] Server process error: ${err.message}`);
  });

  return proc;
}

/**
 * Check if the Python MCP server is available without starting it.
 */
export async function checkPythonServerAvailable(
  opts: PythonServerOptions = {}
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
