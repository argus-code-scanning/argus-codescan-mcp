"""Terraform module and provider pinning (same cases as the npm scanner's test)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from argus.models import Severity
from argus.tools.terraform_deps import check_file, run_terraform_dependency_check

CASES = json.loads((Path(__file__).parent / "fixtures" / "terraform_deps_samples.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_terraform_dependency_rules(case: dict) -> None:
    issues, _ = check_file(case["tf"])
    assert [[i.rule, i.line] for i in issues] == case["expect"]


def test_lockfile_missing_only_for_root_modules(tmp_path: Path) -> None:
    providers = 'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n'
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "main.tf").write_text(
        providers + 'provider "aws" {\n  region = "eu-west-1"\n}\n'
    )
    (tmp_path / "modules" / "vpc").mkdir(parents=True)
    (tmp_path / "modules" / "vpc" / "versions.tf").write_text(providers)  # child module
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "main.tf").write_text('terraform {\n  backend "s3" {}\n}\n')
    (tmp_path / "locked" / ".terraform.lock.hcl").write_text("")
    (tmp_path / "examples" / "demo").mkdir(parents=True)
    (tmp_path / "examples" / "demo" / "main.tf").write_text('provider "aws" {}\n')

    result = asyncio.run(run_terraform_dependency_check(str(tmp_path)))
    missing = {f.file: f for f in result.findings if f.rule_id == "tf-lockfile-missing"}
    assert set(missing) == {"live/.terraform.lock.hcl", "examples/demo/.terraform.lock.hcl"}
    assert missing["live/.terraform.lock.hcl"].severity == Severity.LOW
    # Examples are lowered one level, like the rule packs.
    assert missing["examples/demo/.terraform.lock.hcl"].severity == Severity.INFO
    assert missing["examples/demo/.terraform.lock.hcl"].context == "docs"


def test_findings_point_at_the_module(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('\n\nmodule "vpc" {\n  source = "github.com/acme/vpc"\n}\n')
    result = asyncio.run(run_terraform_dependency_check(str(tmp_path)))
    [finding] = result.findings
    assert (finding.file, finding.line, finding.severity) == ("main.tf", 3, Severity.MEDIUM)
    assert finding.title == 'Git module "vpc" has no ?ref=, so it follows the default branch'
