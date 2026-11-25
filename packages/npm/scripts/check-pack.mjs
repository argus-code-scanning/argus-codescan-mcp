#!/usr/bin/env node
/**
 * Refuse to publish a package without its compiled code. A stray ignore file in dist/
 * (e.g. the `*` .gitignore that `uv build` writes into its output folder) makes `npm pack`
 * silently leave dist/ out, so `npx argus-codescan` would fail for everyone.
 */
import { execFileSync } from "node:child_process";

const REQUIRED = [
  "dist/cli.js",
  "dist/index.js",
  "dist/scan-cli.js",
  "dist/scanners/native-sast.js",
  "dist/scanners/privacy.js",
  "dist/scanners/shared-rules.generated.js",
];

const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});
const files = new Set(JSON.parse(out)[0].files.map((f) => f.path.replace(/\\/g, "/")));
const missing = REQUIRED.filter((f) => !files.has(f));
if (missing.length) {
  console.error(`Refusing to publish: the package is missing ${missing.join(", ")}.`);
  console.error("Check dist/ for a stray .gitignore or .npmignore, then: rm -rf dist && npm run build");
  process.exit(1);
}
console.log(`package contents OK (${files.size} files)`);
