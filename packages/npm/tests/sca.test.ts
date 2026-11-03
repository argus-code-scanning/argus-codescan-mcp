import { execa } from "execa";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { findPackageDirs, parseAuditFindings, runNpmAuditSca } from "../src/scanners/sca.js";

vi.mock("execa", () => ({ execa: vi.fn() }));

// Shapes from real `npm audit --json` output (see packages/python/tests/test_sca.py).
const NPM_FULL = {
  vulnerabilities: {
    "js-yaml": {
      severity: "high",
      via: [
        {
          source: 1,
          title: "JS-YAML: Quadratic CPU consumption",
          url: "https://github.com/advisories/GHSA-5p4m-2wfm-xmqj",
          severity: "high",
          range: "4.0.0 - 4.3.1",
        },
      ],
    },
    "brace-expansion": {
      severity: "high",
      via: [
        {
          source: 2,
          title: "brace-expansion: DoS via unbounded expansion length",
          url: "https://github.com/advisories/GHSA-mh99-v99m-4gvg",
          severity: "high",
          range: "<=1.1.20",
        },
        {
          source: 3,
          title: "brace-expansion: Quadratic-time expansion",
          url: "https://github.com/advisories/GHSA-q2hr-2g5m-vwhr",
          severity: "moderate",
          range: "<=1.1.20",
        },
      ],
    },
    vitest: {
      severity: "critical",
      via: [
        {
          source: 4,
          title: "When Vitest UI server is listening, arbitrary file can be read",
          url: "https://github.com/advisories/GHSA-5xrq-8626-4rwp",
          severity: "critical",
          range: "<=4.1.10",
        },
        "vite",
      ],
    },
    // Only points at another package's advisory: no finding of its own.
    "vite-node": { severity: "moderate", via: ["vite"] },
  },
};
const NPM_PROD = {
  vulnerabilities: {
    "js-yaml": NPM_FULL.vulnerabilities["js-yaml"],
    "brace-expansion": NPM_FULL.vulnerabilities["brace-expansion"],
  },
};

const execaMock = vi.mocked(execa);
let root: string;
let audited: string[];

async function put(path: string, content = "{}"): Promise<void> {
  await mkdir(join(root, path, ".."), { recursive: true });
  await writeFile(join(root, path), content);
}

/** packages/npm and extensions/vscode have lockfiles; packages/npm/workspace is a member. */
async function npmTree(): Promise<void> {
  for (const project of ["packages/npm", "extensions/vscode"]) {
    await put(`${project}/package.json`);
    await put(`${project}/package-lock.json`);
  }
  await put("packages/npm/workspace/package.json");
  await put("packages/npm/node_modules/dep/package.json");
}

function mockAudit(full: object = NPM_FULL, prod: object = NPM_PROD): void {
  execaMock.mockImplementation((async (_cmd: string, args: string[], opts: { cwd: string }) => {
    if (!args.includes("--omit=dev")) audited.push(opts.cwd);
    return { stdout: JSON.stringify(args.includes("--omit=dev") ? prod : full) };
  }) as never);
}

beforeEach(async () => {
  vi.resetAllMocks();
  audited = [];
  root = await mkdtemp(join(tmpdir(), "argus-sca-test-"));
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("runNpmAuditSca", () => {
  it("audits every project with a lockfile and skips node_modules", async () => {
    await npmTree();
    mockAudit({ vulnerabilities: {} }, { vulnerabilities: {} });

    const result = await runNpmAuditSca(root);

    expect(audited.sort()).toEqual([
      join(root, "extensions/vscode"),
      join(root, "packages/npm"),
    ]);
    expect(result.projects?.sort()).toEqual(audited);
    expect(execaMock).toHaveBeenCalledWith(
      "npm",
      ["audit", "--json", "--omit=dev"],
      expect.objectContaining({ cwd: join(root, "packages/npm") }),
    );
    // The workspace member is covered by the packages/npm lockfile.
    expect(result.errors).toEqual([]);
  });

  it("reports packages that no lockfile covers", async () => {
    await npmTree();
    await put("tools/script/package.json");
    mockAudit({ vulnerabilities: {} }, { vulnerabilities: {} });

    const result = await runNpmAuditSca(root);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain("npm audit needs a lockfile");
    expect(result.errors[0]).toContain(join(root, "tools/script"));
    expect(result.errors[0]).not.toContain("workspace");
  });

  it("emits one finding per advisory with the advisory's severity and scope", async () => {
    await npmTree();
    mockAudit();

    const result = await runNpmAuditSca(join(root, "packages/npm"));

    const byId = Object.fromEntries(result.findings.map((f) => [f.ruleId, f]));
    expect(Object.keys(byId).sort()).toEqual([
      "GHSA-5p4m-2wfm-xmqj",
      "GHSA-5xrq-8626-4rwp",
      "GHSA-mh99-v99m-4gvg",
      "GHSA-q2hr-2g5m-vwhr",
    ]);
    expect(byId["GHSA-q2hr-2g5m-vwhr"].severity).toBe("moderate");
    expect(byId["GHSA-q2hr-2g5m-vwhr"].package).toBe("brace-expansion");
    expect(byId["GHSA-5p4m-2wfm-xmqj"].description).toMatch(/^\[runtime dependency\] js-yaml/);
    expect(byId["GHSA-5xrq-8626-4rwp"].description).toMatch(/^\[dev dependency\] vitest/);
    expect(byId["GHSA-5xrq-8626-4rwp"].title).toBe(
      "vitest: When Vitest UI server is listening, arbitrary file can be read",
    );
    // Relative to the scanned folder, with forward slashes on every OS.
    expect(byId["GHSA-5p4m-2wfm-xmqj"].file).toBe("package-lock.json");
    expect(result.findings[0].severity).toBe("critical");
  });

  it("accepts a package.json path as the target", async () => {
    await npmTree();
    mockAudit({ vulnerabilities: {} }, { vulnerabilities: {} });

    await runNpmAuditSca(join(root, "extensions/vscode/package.json"));

    expect(audited).toEqual([join(root, "extensions/vscode")]);
  });

  it("does not follow symlinked directories", async () => {
    const outside = await mkdtemp(join(tmpdir(), "argus-sca-outside-"));
    try {
      await writeFile(join(outside, "package.json"), "{}");
      await writeFile(join(outside, "package-lock.json"), "{}");
      await put("package.json");
      await put("package-lock.json");
      // "junction" needs no admin rights on Windows; ignored elsewhere.
      await symlink(outside, join(root, "linked"), "junction");
      mockAudit({ vulnerabilities: {} }, { vulnerabilities: {} });

      await runNpmAuditSca(root);

      expect(audited).toEqual([root]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("records npm audit errors per project", async () => {
    await npmTree();
    mockAudit({ error: { code: "ENOLOCK", summary: "lockfile is broken" } });

    const result = await runNpmAuditSca(join(root, "packages/npm"));

    expect(result.findings).toEqual([]);
    expect(result.projects).toEqual([]);
    expect(result.errors[0]).toContain("lockfile is broken");
  });

  it("errors when there is no package.json", async () => {
    const result = await runNpmAuditSca(root);

    expect(result.errors).toEqual([`No package.json found at ${root}`]);
    expect(execaMock).not.toHaveBeenCalled();
  });
});

describe("findPackageDirs / parseAuditFindings", () => {
  it("finds nested package dirs in sorted order", async () => {
    await npmTree();
    expect(findPackageDirs(root)).toEqual(
      ["extensions/vscode", "packages/npm", "packages/npm/workspace"].map((p) => join(root, p)),
    );
  });

  it("skips string-only via entries", () => {
    const findings = parseAuditFindings(NPM_FULL, new Set());
    expect(findings.map((f) => f.package)).not.toContain("vite-node");
  });
});
