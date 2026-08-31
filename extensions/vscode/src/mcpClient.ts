/**
 * MCP client for communicating with the argus-scan Python server.
 *
 * Uses JSON-RPC 2.0 over stdio with Content-Length framing (MCP spec).
 */

import * as cp from "child_process";
import * as vscode from "vscode";
import type { AggregatedReport, ScanOptions } from "./types.js";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
};

export class McpClient implements vscode.Disposable {
  private process: cp.ChildProcess | null = null;
  private buffer = Buffer.alloc(0);
  private requestId = 0;
  private pending = new Map<number, PendingRequest>();
  private initialized = false;
  private readonly outputChannel: vscode.OutputChannel;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  async start(): Promise<void> {
    if (this.process) {
      return; // already running
    }

    const config = vscode.workspace.getConfiguration("argus-scan");
    const customCommand = config.get<string>("mcpServerCommand") || "";

    const { command, args } = await this.resolveCommand(customCommand);
    this.outputChannel.appendLine(`[MCP] Starting server: ${command} ${args.join(" ")}`);

    this.process = cp.spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    this.process.stdout!.on("data", (data: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, data]);
      this.processBuffer();
    });

    this.process.stderr!.on("data", (data: Buffer) => {
      this.outputChannel.appendLine(`[MCP stderr] ${data.toString().trim()}`);
    });

    this.process.on("exit", (code) => {
      this.outputChannel.appendLine(`[MCP] Server exited with code ${code}`);
      this.process = null;
      this.initialized = false;
      // Reject all pending requests
      for (const [, { reject }] of this.pending) {
        reject(new Error("MCP server process exited"));
      }
      this.pending.clear();
    });

    this.process.on("error", (err) => {
      this.outputChannel.appendLine(`[MCP] Server error: ${err.message}`);
      vscode.window.showErrorMessage(
        `argus-scan server failed to start: ${err.message}\n` +
          `Make sure argus-scan is installed: pip install argus-scan`
      );
    });

    await this.initialize();
  }

  private async resolveCommand(
    customCommand: string
  ): Promise<{ command: string; args: string[] }> {
    if (customCommand) {
      const parts = customCommand.split(" ");
      return { command: parts[0], args: parts.slice(1) };
    }

    // Prefer dedicated MCP entrypoints — bare argus-scan prints CLI help.
    const candidates: Array<{ command: string; args: string[] }> = [
      { command: "argus-mcp", args: [] },
      { command: "argus-scan", args: ["mcp"] },
      { command: "argus", args: ["mcp"] },
      { command: "uvx", args: ["--from", "argus-scan", "argus-mcp"] },
      { command: "npx", args: ["-y", "argus-codescan", "mcp"] },
    ];

    for (const candidate of candidates) {
      try {
        await this.checkExecutable(candidate.command);
        return candidate;
      } catch {
        // try next
      }
    }

    // Fall back to python -m
    return {
      command: "python3",
      args: ["-m", "argus.server"],
    };
  }

  private checkExecutable(command: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const proc = cp.spawn(command, ["--version"], { stdio: "pipe" });
      proc.on("error", reject);
      proc.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`exit ${code}`))));
    });
  }

  private async initialize(): Promise<void> {
    const response = await this.sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "argus-scan-vscode", version: "0.1.0" },
    });

    await this.sendNotification("notifications/initialized", {});
    this.initialized = true;
    this.outputChannel.appendLine("[MCP] Server initialized successfully");
  }

  private processBuffer(): void {
    while (true) {
      const headerEnd = this.buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }

      const headerText = this.buffer.subarray(0, headerEnd).toString("utf-8");
      const match = /Content-Length:\s*(\d+)/i.exec(headerText);
      if (!match) {
        this.buffer = this.buffer.subarray(headerEnd + 4);
        continue;
      }

      const contentLength = Number.parseInt(match[1], 10);
      const bodyStart = headerEnd + 4;
      if (this.buffer.length < bodyStart + contentLength) {
        return;
      }

      const body = this.buffer.subarray(bodyStart, bodyStart + contentLength).toString("utf-8");
      this.buffer = this.buffer.subarray(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body) as JsonRpcResponse;
        if ("id" in msg && msg.id !== undefined) {
          const pending = this.pending.get(msg.id);
          if (pending) {
            this.pending.delete(msg.id);
            if (msg.error) {
              pending.reject(new Error(msg.error.message));
            } else {
              pending.resolve(msg.result);
            }
          }
        }
      } catch {
        // ignore malformed payloads
      }
    }
  }

  private writeMessage(payload: unknown): void {
    if (!this.process?.stdin) {
      return;
    }
    const body = JSON.stringify(payload);
    const header = `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n`;
    this.process.stdin.write(header + body);
  }

  private sendRequest(method: string, params: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.process) {
        reject(new Error("MCP server not running"));
        return;
      }

      const id = ++this.requestId;
      this.pending.set(id, { resolve, reject });

      const request: JsonRpcRequest = {
        jsonrpc: "2.0",
        id,
        method,
        params,
      };

      this.writeMessage(request);
    });
  }

  private async sendNotification(method: string, params: unknown): Promise<void> {
    if (!this.process) return;
    this.writeMessage({ jsonrpc: "2.0", method, params });
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<string> {
    if (!this.initialized) {
      await this.start();
    }

    const result = await this.sendRequest("tools/call", {
      name,
      arguments: args,
    }) as { content?: Array<{ type: string; text: string }> };

    const content = result?.content ?? [];
    return content
      .filter((c) => c.type === "text")
      .map((c) => c.text)
      .join("\n");
  }

  async scanSast(target: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_sast", {
      target,
      ...(options.tools && { tools: options.tools }),
      ...(options.semgrepConfig && { semgrep_config: options.semgrepConfig }),
      ...(options.timeout && { timeout: options.timeout }),
      ...(options.format && { format: options.format }),
    });
  }

  async scanSca(target: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_sca", { target, ...options });
  }

  async scanSecrets(target: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_secrets", { target, ...options });
  }

  async scanIac(target: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_iac", { target, ...options });
  }

  async scanDast(targetUrl: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_dast", { target_url: targetUrl, ...options });
  }

  async scanContainer(image: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_container", { image, ...options });
  }

  async scanAll(target: string, options: ScanOptions = {}): Promise<string> {
    return this.callTool("scan_all", {
      target,
      ...(options.targetUrl && { target_url: options.targetUrl }),
      ...(options.containerImage && { container_image: options.containerImage }),
      ...(options.timeout && { timeout: options.timeout }),
      format: options.format ?? "markdown",
    });
  }

  async checkTools(): Promise<string> {
    return this.callTool("check_tools", {});
  }

  async applyFix(args: {
    target: string;
    file: string;
    tool: string;
    scan_type?: string;
    rule_id?: string;
    line?: number;
    fix_guidance?: string;
    apply?: boolean;
    semgrep_config?: string;
  }): Promise<string> {
    return this.callTool("apply_fix", args);
  }

  stop(): void {
    if (this.process) {
      this.process.kill();
      this.process = null;
      this.initialized = false;
    }
  }

  dispose(): void {
    this.stop();
  }
}
