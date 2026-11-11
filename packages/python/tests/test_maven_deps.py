"""Maven / Gradle dependencies without Trivy (OSV is mocked: no network in tests)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from argus.models import Severity
from argus.tools import malicious_packages as mp
from argus.tools import maven_deps as md

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.4.0</version>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <jackson.version>${jackson.base}</jackson.version>
    <jackson.base>2.13.0</jackson.base>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.17</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>shared</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.0,5.0)</version></dependency>
    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1.0-SNAPSHOT</version></dependency>
  </dependencies>
</project>
"""


def _names(packages: Any) -> set[tuple[str, str]]:
    return {(p.name, p.version) for p in packages}


def test_pom_resolves_properties_and_skips_unresolved_or_ranges() -> None:
    assert _names(md.pom_packages(POM)) == {
        ("org.springframework:spring-core", "5.3.17"),
        ("org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("com.fasterxml.jackson.core:jackson-databind", "2.13.0"),
        ("com.example:shared", "1.4.0"),
    }
    assert all(p.ecosystem == "Maven" for p in md.pom_packages(POM))


def test_pom_with_a_dtd_is_refused() -> None:
    hostile = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa">]><project></project>'
    assert list(md.pom_packages(hostile)) == []


def test_gradle_lockfile() -> None:
    text = (
        "# This is a Gradle generated file\n"
        "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n"
        "org.yaml:snakeyaml:1.33=runtimeClasspath\n"
        "empty=annotationProcessor\n"
    )
    assert _names(md.gradle_lockfile_packages(text)) == {
        ("com.google.guava:guava", "31.1-jre"),
        ("org.yaml:snakeyaml", "1.33"),
    }


def test_build_gradle_groovy_and_kotlin_dsl() -> None:
    groovy = """
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:2.6.6'
    testImplementation "junit:junit:4.13.2"
    implementation group: 'commons-io', name: 'commons-io', version: '2.6'
    implementation "org.example:dynamic:1.+"
    implementation "org.example:templated:$ver"
}
"""
    kts = """
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.9.0")
    api("org.jetbrains.kotlin:kotlin-stdlib:${'$'}kotlinVersion")
}
"""
    assert _names(md.gradle_build_packages(groovy)) == {
        ("org.springframework.boot:spring-boot-starter-web", "2.6.6"),
        ("junit:junit", "4.13.2"),
        ("commons-io:commons-io", "2.6"),
    }
    assert _names(md.gradle_build_packages(kts)) == {("com.squareup.okhttp3:okhttp", "4.9.0")}


@pytest.mark.skipif(mp._toml is None, reason="no TOML parser on this Python")
def test_gradle_version_catalog() -> None:
    catalog = """
[versions]
jackson = "2.13.0"

[libraries]
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
okhttp = "com.squareup.okhttp3:okhttp:4.9.0"
guava = { group = "com.google.guava", name = "guava", version = "31.1-jre" }
strict = { module = "org.example:strict", version = { strictly = "1.2.3" } }
unversioned = { module = "org.example:bom-managed" }
"""
    assert _names(md.version_catalog_packages(catalog)) == {
        ("com.fasterxml.jackson.core:jackson-databind", "2.13.0"),
        ("com.squareup.okhttp3:okhttp", "4.9.0"),
        ("com.google.guava:guava", "31.1-jre"),
        ("org.example:strict", "1.2.3"),
    }


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pom.xml").write_text(POM)
    (tmp_path / "gradle").mkdir()
    (tmp_path / "build.gradle").write_text(
        "dependencies { implementation 'org.yaml:snakeyaml:1.33' }\n"
    )
    for skipped in ("target", ".gradle", "build"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "pom.xml").write_text(POM)
    return tmp_path


def test_maven_files_are_collected_with_artifact_lines(tmp_path: Path) -> None:
    packages, lockfiles, errors = mp.collect_packages(_project(tmp_path))
    assert errors == []
    assert sorted(lockfiles) == ["build.gradle", "pom.xml"]
    log4j = mp.Package("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    ((lockfile, line),) = packages[log4j]
    assert lockfile == "pom.xml"
    assert "log4j-core" in POM.splitlines()[line - 1]


class FakeOSV:
    def __init__(self, ids: dict[tuple[str, str], list[str]]) -> None:
        self.ids = ids

    def __call__(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for q in queries:
            found = self.ids.get((q["package"]["name"], q["version"]), [])
            out.append({"vulns": [{"id": i} for i in found]} if found else {})
        return out


LOG4SHELL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "aliases": ["CVE-2021-44228"],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.3.1"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.4"}, {"fixed": "2.12.2"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]},
            ],
        }
    ],
}


@pytest.fixture
def online(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    monkeypatch.setattr(md, "is_tool_available", lambda name: False)
    return monkeypatch


@pytest.mark.asyncio
async def test_java_cve_is_reported_with_cve_and_fixed_version(
    tmp_path: Path, online: pytest.MonkeyPatch
) -> None:
    _project(tmp_path)
    online.setattr(
        mp,
        "_post_querybatch",
        FakeOSV(
            {
                ("org.apache.logging.log4j:log4j-core", "2.14.1"): [
                    "GHSA-jfh8-c2jp-5v3q",
                    "MAL-2099-1",
                ]
            }
        ),
    )
    online.setattr(md, "_fetch_vuln", lambda vuln_id: LOG4SHELL)

    result = await md.run_java_dependency_check(str(tmp_path))

    assert result.errors == []
    (finding,) = result.findings  # MAL- ids are left to the known-malicious check
    assert finding.severity == Severity.CRITICAL
    assert (
        finding.title
        == "org.apache.logging.log4j:log4j-core@2.14.1: Remote code injection in Log4j"
    )
    assert finding.cve == "CVE-2021-44228"
    assert finding.file == "pom.xml"
    # The nearest fix above 2.14.1, not every release line's fix.
    assert finding.fix_guidance == "Upgrade org.apache.logging.log4j:log4j-core to 2.15.0 or later."
    assert finding.references == ["https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"]


@pytest.mark.asyncio
async def test_skipped_when_trivy_is_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    monkeypatch.setattr(md, "is_tool_available", lambda name: name == "trivy")
    _project(tmp_path)
    result = await md.run_java_dependency_check(str(tmp_path))
    assert result.findings == [] and "Trivy" in result.metadata["skipped"]


@pytest.mark.asyncio
async def test_offline_is_a_note(tmp_path: Path, online: pytest.MonkeyPatch) -> None:
    import urllib.error

    _project(tmp_path)

    def offline(_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise urllib.error.URLError("offline")

    online.setattr(mp, "_post_querybatch", offline)
    result = await md.run_java_dependency_check(str(tmp_path))
    assert result.findings == [] and "network unavailable" in result.errors[0]


@pytest.mark.asyncio
async def test_no_java_project_means_no_request(tmp_path: Path, online: pytest.MonkeyPatch) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

    def must_not_call(_queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise AssertionError("no Maven packages, no request")

    online.setattr(mp, "_post_querybatch", must_not_call)
    result = await md.run_java_dependency_check(str(tmp_path))
    assert result.metadata["packages_checked"] == 0


@pytest.mark.asyncio
async def test_known_malicious_check_now_covers_maven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ARGUS_NO_NETWORK", raising=False)
    _project(tmp_path)
    monkeypatch.setattr(
        mp, "_post_querybatch", FakeOSV({("org.yaml:snakeyaml", "1.33"): ["MAL-2099-7"]})
    )
    result = await mp.run_malicious_package_check(str(tmp_path))
    (finding,) = result.findings
    assert finding.title == "Known malicious package: org.yaml:snakeyaml@1.33"
    assert finding.file == "build.gradle"
