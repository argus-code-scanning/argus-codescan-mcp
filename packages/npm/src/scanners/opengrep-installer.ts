import { chmodSync, createWriteStream, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

const OPENGREP_VERSION = "v1.25.0";
const CACHE_DIR = join(homedir(), ".argus-codescan", "bin");

interface PlatformAsset {
  asset: string;
  exeName: string;
}

function resolvePlatformAsset(): PlatformAsset | null {
  const { platform, arch } = process;
  if (platform === "darwin" && arch === "arm64") {
    return { asset: "opengrep_osx_arm64", exeName: "opengrep" };
  }
  if (platform === "darwin" && arch === "x64") {
    return { asset: "opengrep_osx_x86", exeName: "opengrep" };
  }
  if (platform === "linux" && arch === "arm64") {
    return { asset: "opengrep_manylinux_aarch64", exeName: "opengrep" };
  }
  if (platform === "linux" && arch === "x64") {
    return { asset: "opengrep_manylinux_x86", exeName: "opengrep" };
  }
  if (platform === "win32" && arch === "x64") {
    return { asset: "opengrep_windows_x86.exe", exeName: "opengrep.exe" };
  }
  return null;
}

export function opengrepCachePath(): string | null {
  const platform = resolvePlatformAsset();
  if (!platform) return null;
  return join(CACHE_DIR, platform.exeName);
}

/** Download Opengrep (Semgrep-compatible) binary — no pip/Python required. */
export async function ensureOpengrepBinary(): Promise<string | null> {
  const platform = resolvePlatformAsset();
  if (!platform) return null;

  const dest = join(CACHE_DIR, platform.exeName);
  if (existsSync(dest)) return dest;

  mkdirSync(CACHE_DIR, { recursive: true });

  const url =
    `https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${platform.asset}`;

  const response = await fetch(url);
  if (!response.ok || !response.body) {
    return null;
  }

  await pipeline(Readable.fromWeb(response.body as never), createWriteStream(dest));
  chmodSync(dest, 0o755);
  return dest;
}

export function isOpengrepSupportedPlatform(): boolean {
  return resolvePlatformAsset() !== null;
}
