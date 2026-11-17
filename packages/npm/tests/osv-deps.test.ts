/** Dependency vulnerabilities for every ecosystem (same cases as argus-scan tests/test_osv_deps.py). OSV is mocked. */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fixAdvice, type OsvClient, type OsvRecord, type Pkg, readLockfile, runOsvDependencyCheck } from "../src/scanners/osv-deps.js";

const GO_MOD = `module example.com/svc

go 1.22

toolchain go1.22.1

require github.com/gin-gonic/gin v1.9.0

require (
\tgolang.org/x/net v0.7.0 // indirect
\tgithub.com/pkg/errors v0.9.1+incompatible
)

replace (
\texample.com/old v1.0.0 => example.com/new v1.1.0
)
`;
const PUBSPEC_LOCK = `packages:
  http:
    dependency: "direct main"
    source: hosted
    version: "0.13.2"
  mocktail:
    dependency: "direct dev"
    source: hosted
    version: "1.0.0"
  meta:
    dependency: transitive
    source: hosted
    version: "1.9.1"
  flutter:
    dependency: "direct main"
    source: sdk
    version: "0.0.0"
`;
const CARGO_LOCK = `version = 3

[[package]]
name = "cli"
version = "0.1.0"
dependencies = ["chrono"]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "time 0.1.43",
]

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
`;
const GEMFILE_LOCK = `GEM
  remote: https://rubygems.org/
  specs:
    loofah (2.19.0)
      nokogiri (>= 1.5.9)
    nokogiri (1.13.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.6.0)

DEPENDENCIES
  loofah
`;
const NUGET_LOCK = JSON.stringify({
  version: 1,
  dependencies: {
    "net8.0": {
      "Newtonsoft.Json": { type: "Direct", resolved: "12.0.1" },
      "Html.Abstractions": { type: "Direct", resolved: "2.1.0", dependencies: { "System.Text.Encodings.Web": "4.5.0" } },
      "System.Text.Encodings.Web": { type: "Transitive", resolved: "4.5.0" },
      MyLib: { type: "Project" },
    },
  },
});
const UV_LOCK = `version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.19.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.24.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
`;

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "argus-osv-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function lock(dir: string, name: string, text: string): Promise<string> {
  await mkdir(join(root, dir), { recursive: true });
  await writeFile(join(root, dir, name), text);
  return join(root, dir, name);
}
const triples = (pkgs: Pkg[]) => pkgs.map((p) => [p.ecosystem, p.name, p.version]).sort();

describe("lockfile readers", () => {
  it("go.mod: requires and the toolchain, not replace blocks", async () => {
    expect(triples(readLockfile(await lock("go", "go.mod", GO_MOD)).packages)).toEqual(
      [["Go", "github.com/gin-gonic/gin", "v1.9.0"], ["Go", "github.com/pkg/errors", "v0.9.1"], ["Go", "golang.org/x/net", "v0.7.0"], ["Go", "stdlib", "1.22.1"]].sort(),
    );
  });

  it("pubspec.lock: hosted packages only, dev from 'direct dev'", async () => {
    const { packages, graph } = readLockfile(await lock("app", "pubspec.lock", PUBSPEC_LOCK));
    expect(triples(packages)).toEqual([["Pub", "http", "0.13.2"], ["Pub", "meta", "1.9.1"], ["Pub", "mocktail", "1.0.0"]]);
    expect(graph.isDevOnly("mocktail")).toBe(true);
    expect(graph.isDevOnly("http")).toBe(false);
  });

  it("Cargo.lock, Gemfile.lock and packages.lock.json give install paths", async () => {
    const cargo = readLockfile(await lock("rust", "Cargo.lock", CARGO_LOCK));
    expect(triples(cargo.packages)).toEqual([["crates.io", "chrono", "0.4.19"], ["crates.io", "time", "0.1.43"]]);
    expect(cargo.graph.pathsTo("time")).toEqual(["chrono › time"]);
    const gems = readLockfile(await lock("ruby", "Gemfile.lock", GEMFILE_LOCK));
    expect(gems.packages.find((p) => p.name === "nokogiri")?.version).toBe("1.13.0");
    expect(gems.graph.pathsTo("nokogiri")).toEqual(["loofah › nokogiri"]);
    const nuget = readLockfile(await lock("dotnet", "packages.lock.json", NUGET_LOCK));
    expect(nuget.packages.map((p) => p.name).sort()).toEqual(["Html.Abstractions", "Newtonsoft.Json", "System.Text.Encodings.Web"]);
    expect(nuget.graph.pathsTo("System.Text.Encodings.Web")).toEqual(["Html.Abstractions › System.Text.Encodings.Web"]);
  });

  it("uv.lock: editable project gives direct and dev dependencies", async () => {
    const { packages, graph } = readLockfile(await lock("py", "uv.lock", UV_LOCK));
    expect(triples(packages)).toEqual([["PyPI", "pytest", "7.0.0"], ["PyPI", "requests", "2.19.0"], ["PyPI", "urllib3", "1.24.1"]]);
    expect(graph.pathsTo("urllib3")).toEqual(["requests › urllib3"]);
    expect(graph.isDevOnly("pytest")).toBe(true);
  });

  it("yarn.lock: packages, edges and direct deps from package.json", async () => {
    await lock("web", "package.json", JSON.stringify({ dependencies: { express: "^4" }, devDependencies: { jest: "^29" } }));
    const yarn = `# yarn lockfile v1\n\nexpress@^4:\n  version "4.17.1"\n  dependencies:\n    qs "6.7.0"\n\nqs@6.7.0:\n  version "6.7.0"\n\njest@^29:\n  version "29.0.0"\n`;
    const { packages, graph } = readLockfile(await lock("web", "yarn.lock", yarn));
    expect(triples(packages)).toEqual([["npm", "express", "4.17.1"], ["npm", "jest", "29.0.0"], ["npm", "qs", "6.7.0"]]);
    expect(graph.pathsTo("qs")).toEqual(["express › qs"]);
    expect(graph.isDevOnly("jest")).toBe(true);
  });
});

const ADVISORIES: Record<string, OsvRecord> = {
  "GHSA-time-0001": { summary: "Segmentation fault in time", database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "time" }, ranges: [{ events: [{ fixed: "0.2.23" }] }] }] },
  "GHSA-noko-0001": { summary: "nokogiri issue one", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "nokogiri" }, ranges: [{ events: [{ fixed: "1.13.4" }] }] }] },
  "GHSA-noko-0002": { summary: "nokogiri issue two", database_specific: { severity: "CRITICAL" }, affected: [{ package: { name: "nokogiri" }, ranges: [{ events: [{ fixed: "1.16.5" }] }] }] },
  "GO-2024-0001": { summary: "net/http issue", aliases: ["GHSA-gogo-0001"], affected: [{ package: { name: "stdlib" }, ranges: [{ events: [{ fixed: "1.22.4" }] }] }] },
  "GHSA-gogo-0001": { database_specific: { severity: "LOW" } },
  "GHSA-mock-0001": { summary: "mocktail issue", database_specific: { severity: "HIGH" }, affected: [] },
};
const IDS: Record<string, string[]> = {
  "crates.io/time": ["GHSA-time-0001"],
  "RubyGems/nokogiri": ["GHSA-noko-0001", "GHSA-noko-0002", "MAL-2024-1"],
  "Go/stdlib": ["GO-2024-0001"],
  "Pub/mocktail": ["GHSA-mock-0001"],
};
const mockClient: OsvClient = {
  async queryIds(pkgs) {
    return new Map(pkgs.filter((p) => IDS[`${p.ecosystem}/${p.name}`]).map((p) => [p, IDS[`${p.ecosystem}/${p.name}`]]));
  },
  async details(ids) {
    return new Map(ids.filter((i) => ADVISORIES[i]).map((i) => [i, ADVISORIES[i]]));
  },
};

describe("OSV dependency check", () => {
  beforeEach(async () => {
    await lock("rust", "Cargo.lock", CARGO_LOCK);
    await lock("ruby", "Gemfile.lock", GEMFILE_LOCK);
    await lock("go", "go.mod", GO_MOD);
    await lock("app", "pubspec.lock", PUBSPEC_LOCK);
  });

  it("one finding per package with paths, severity and the fix for every advisory", async () => {
    const result = await runOsvDependencyCheck(root, mockClient);
    const byPkg = Object.fromEntries(result.findings.map((f) => [f.package, f]));
    expect(Object.keys(byPkg).sort()).toEqual(["mocktail", "nokogiri", "stdlib", "time"]);

    expect(byPkg.nokogiri.title).toBe("nokogiri: 2 known vulnerabilities");
    expect(byPkg.nokogiri.severity).toBe("critical");
    expect(byPkg.nokogiri.paths).toEqual(["loofah › nokogiri"]);
    expect(byPkg.nokogiri.fix).toMatch(/^Upgrade nokogiri to 1\.16\.5: update loofah/);
    expect(byPkg.nokogiri.description).not.toContain("MAL-");

    expect(byPkg.time.file).toBe("rust/Cargo.lock");
    expect(byPkg.time.description).toContain("(via chrono)");
    expect(byPkg.time.fix).toContain("cargo update -p time --precise 0.2.23");

    expect(byPkg.stdlib.title).toBe("Go toolchain: net/http issue");
    expect(byPkg.stdlib.severity).toBe("low");
    expect(byPkg.stdlib.fix).toBe("Build with Go 1.22.4 or later (set `toolchain go1.22.4` in go.mod).");

    expect(byPkg.mocktail.context).toBe("dev-dependency");
    expect(byPkg.mocktail.severity).toBe("moderate");
    expect(byPkg.mocktail.fix).toMatch(/^No patched version of mocktail is published yet/);
  });

  it("skips the lookup without network", async () => {
    process.env.ARGUS_NO_NETWORK = "1";
    try {
      const result = await runOsvDependencyCheck(root, mockClient);
      expect(result.findings).toEqual([]);
      expect(result.notes?.[0]).toContain("network disabled");
    } finally {
      delete process.env.ARGUS_NO_NETWORK;
    }
  });

  it.each([
    ["npm", "npm install lodash@2.0.0"],
    ["PyPI", "set lodash>=2.0.0 in your requirements"],
    ["Go", "go get lodash@v2.0.0"],
    ["Pub", "set lodash: ^2.0.0 in pubspec.yaml"],
    ["crates.io", 'set lodash = "2.0.0" in Cargo.toml'],
    ["RubyGems", "bundle update lodash"],
    ["NuGet", "update the PackageReference for lodash to 2.0.0"],
    ["Packagist", "composer require lodash:^2.0.0"],
  ])("fix advice for %s", (ecosystem, hint) => {
    const pkg: Pkg = { ecosystem, name: "lodash", version: "1.0.0", line: 1 };
    expect(fixAdvice(pkg, "2.0.0", ["lodash"])).toContain(hint);
    expect(fixAdvice(pkg, "2.0.0", ["app › lodash"])).toContain("update app, which brings it in");
    expect(fixAdvice(pkg, "2.0.0", ["lodash"], 1)).toMatch(/1 advisory has no fix yet\.$/);
  });
});
