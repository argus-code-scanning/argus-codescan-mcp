/**
 * Generate MCP server configuration objects for various MCP clients.
 */

export interface McpServerConfig {
  /** For Claude Desktop / Cursor mcp.json */
  claudeDesktop: {
    mcpServers: {
      "argus-scan": {
        command: string;
        args?: string[];
        env?: Record<string, string>;
      };
    };
  };
  /** For programmatic use */
  command: string;
  args: string[];
}

/**
 * Generate an MCP server config for a given installation method.
 *
 * Prefer `argus-mcp` (or `argus mcp`) — bare `argus-scan` prints CLI help.
 */
export function getMcpServerConfig(
  method: "pip" | "uvx" | "npx" = "uvx"
): McpServerConfig {
  const configs: Record<
    "pip" | "uvx" | "npx",
    { command: string; args: string[] }
  > = {
    pip: { command: "argus-mcp", args: [] },
    uvx: { command: "uvx", args: ["--from", "argus-scan", "argus-mcp"] },
    npx: { command: "npx", args: ["-y", "argus-codescan", "mcp"] },
  };

  const { command, args } = configs[method];

  return {
    command,
    args,
    claudeDesktop: {
      mcpServers: {
        "argus-scan": {
          command,
          ...(args.length > 0 && { args }),
        },
      },
    },
  };
}
