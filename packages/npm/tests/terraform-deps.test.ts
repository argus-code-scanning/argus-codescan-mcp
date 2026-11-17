/** Terraform module and provider pinning, same cases as argus-scan tests/test_terraform_deps.py. */
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkTerraformFile, runTerraformDependencyCheck } from "../src/scanners/terraform-deps.js";

const CASES: { name: string; tf: string; expect: [string, number][] }[] = JSON.parse(
  readFileSync(new URL("./fixtures/terraform_deps_samples.json", import.meta.url), "utf8"),
);

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-tf-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("Terraform dependency pinning", () => {
  it.each(CASES)("$name", ({ tf, expect: expected }) => {
    expect(checkTerraformFile(tf).issues.map((i) => [i.rule, i.line])).toEqual(expected);
  });

  it("asks for a lockfile only in root modules, lowered in examples", async () => {
    const providers =
      'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n';
    await mkdir(join(root, "live"));
    await writeFile(join(root, "live", "main.tf"), `${providers}provider "aws" {\n  region = "eu-west-1"\n}\n`);
    await mkdir(join(root, "modules", "vpc"), { recursive: true });
    await writeFile(join(root, "modules", "vpc", "versions.tf"), providers);
    await mkdir(join(root, "locked"));
    await writeFile(join(root, "locked", "main.tf"), 'terraform {\n  backend "s3" {}\n}\n');
    await writeFile(join(root, "locked", ".terraform.lock.hcl"), "");
    await mkdir(join(root, "examples", "demo"), { recursive: true });
    await writeFile(join(root, "examples", "demo", "main.tf"), 'provider "aws" {}\n');

    const result = await runTerraformDependencyCheck(root);
    const missing = Object.fromEntries(
      result.findings.filter((f) => f.ruleId === "tf-lockfile-missing").map((f) => [f.file, f]),
    );
    expect(Object.keys(missing).sort()).toEqual(["examples/demo/.terraform.lock.hcl", "live/.terraform.lock.hcl"]);
    expect(missing["live/.terraform.lock.hcl"].severity).toBe("low");
    expect(missing["examples/demo/.terraform.lock.hcl"].severity).toBe("info");
  });

  it("points at the module block", async () => {
    await writeFile(join(root, "main.tf"), '\n\nmodule "vpc" {\n  source = "github.com/acme/vpc"\n}\n');
    const [finding] = (await runTerraformDependencyCheck(root)).findings;
    expect([finding.file, finding.line, finding.severity]).toEqual(["main.tf", 3, "moderate"]);
  });
});
