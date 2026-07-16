import which from "which";

export async function isToolAvailable(name: string): Promise<boolean> {
  try {
    await which(name);
    return true;
  } catch {
    return false;
  }
}

export async function runToolsCommand(): Promise<number> {
  console.log("Argus scanners (included vs optional):\n");
  console.log("  ✅ argus-native     Built-in — JS/TS security patterns (always on)");
  console.log("  ✅ eslint-security  Built-in — JS/JSX security + unused vars");
  console.log("  ✅ argus-secrets    Built-in — pattern-based secret detection");
  console.log("  ✅ npm audit        Built-in — dependency scan (scan sca)");
  console.log("  ✅ opengrep         Auto-downloads on first scan (Semgrep-compatible, no pip)\n");

  const optional: Array<[string, string]> = [
    ["semgrep", "Optional — official Semgrep CLI (pip install semgrep)"],
    ["gitleaks", "Optional — deeper secret scan (see gitleaks.io)"],
  ];

  console.log("Optional enhancements (not required):");
  for (const [tool, desc] of optional) {
    const ok = await isToolAvailable(tool);
    console.log(`  ${ok ? "✅" : "○"} ${tool.padEnd(12)} ${desc}`);
  }

  console.log("\nNo Homebrew or manual setup required for basic scanning.");
  console.log("Works on Windows, macOS, and Linux after: npm install -D argus-codescan");
  return 0;
}
