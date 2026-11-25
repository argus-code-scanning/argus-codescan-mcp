import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAiFixPrompt, excerptAround, shouldIncludeCode } from "../src/aiPrompt.js";
import type { Finding } from "../src/types.js";

const base: Finding = {
  title: "Possible command injection",
  severity: "high",
  scan_type: "sast",
  tool: "argus-languages",
  file: "src/run.py",
  line: 8,
  column: 1,
  description: "User input reaches a shell command.",
  cwe: "CWE-78",
  cve: "",
  fix_guidance: "Pass arguments as a list and drop shell=True.",
  rule_id: "command-injection",
  references: [],
};

const code = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join("\n");

test("excerpt is centred on the finding and clamped to the file", () => {
  assert.deepEqual(excerptAround(code, 8).startLine, 2);
  assert.equal(excerptAround(code, 8).lines.length, 13);
  assert.equal(excerptAround(code, 1).startLine, 1);
  assert.equal(excerptAround(code, 20).lines.at(-1), "line 20");
  assert.equal(excerptAround(code, 99).lines.at(-1), "line 20");
});

test("prompt has the finding, guidance, marked code and instructions", () => {
  const prompt = buildAiFixPrompt(base, excerptAround(code, 8, "python"));
  assert.match(prompt, /\*\*Possible command injection\*\*/);
  assert.match(prompt, /Scanner: argus-languages \(rule command-injection\)/);
  assert.match(prompt, /Location: src\/run\.py:8/);
  assert.match(prompt, /CWE: CWE-78/);
  assert.match(prompt, /Suggested fix:\nPass arguments as a list/);
  assert.match(prompt, /```python/);
  assert.match(prompt, /^>\s+8 \| line 8$/m);
  assert.match(prompt, /^\s+7 \| line 7$/m);
  assert.match(prompt, /Don't silence the scanner/);
});

test("secrets findings never include code", () => {
  const secret: Finding = { ...base, scan_type: "secrets", title: "AWS access key", tool: "gitleaks" };
  assert.equal(shouldIncludeCode(secret), false);
  const prompt = buildAiFixPrompt(secret, excerptAround('KEY = "AKIAIOSFODNN7EXAMPLE"', 1));
  assert.doesNotMatch(prompt, /AKIA/);
  assert.match(prompt, /rotate it/);
});

test("very long lines are clipped", () => {
  const prompt = buildAiFixPrompt(base, excerptAround("x".repeat(5000), 1));
  assert.ok(prompt.length < 1500);
});

test("works without a file or code", () => {
  const prompt = buildAiFixPrompt({ ...base, file: "", line: 0, cwe: "", fix_guidance: "" });
  assert.doesNotMatch(prompt, /Location:|CWE:|Suggested fix/);
  assert.match(prompt, /Fix only this issue/);
});
