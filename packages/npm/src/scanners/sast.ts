import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import { runBundledEslint } from "./eslint-runner.js";
import { runNativeSast } from "./native-sast.js";
import { applyPathContext } from "./noise.js";
import { runSemgrepSast } from "./semgrep.js";
import type { ScanResult } from "./types.js";

export { runSemgrepSast } from "./semgrep.js";
export { runNativeSast } from "./native-sast.js";
export { runBundledEslint } from "./eslint-runner.js";

/** Run all SAST tools bundled with the npm package (no brew / no manual install). */
export async function runAllSast(target: string): Promise<ScanResult[]> {
  const [native, eslint, semgrep] = await Promise.all([
    runNativeSast(target),
    runBundledEslint(target),
    runSemgrepSast(target),
  ]);
  const root = lstatSync(target).isDirectory() ? target : dirname(target);
  return [native, applyPathContext(eslint, root), applyPathContext(semgrep, root)];
}
