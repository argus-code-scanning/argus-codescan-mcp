/**
 * argus-scan npm package
 *
 * This package provides utilities to locate, spawn, and interact with
 * the argus-scan Python MCP server from Node.js environments.
 */

export {
  resolvePythonMcpCommand,
  spawnPythonMcpServer,
  checkPythonServerAvailable,
  type PythonServerOptions,
} from "./python-bridge.js";

export { getMcpServerConfig, type McpServerConfig } from "./config.js";

/** Package version */
export const VERSION = "0.1.0";
