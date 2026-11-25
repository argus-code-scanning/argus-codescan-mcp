"""Hardcoded personal data rules, used by `argus scan pii` (#52)."""

from __future__ import annotations

import pytest

from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

RULES = {r.id: r for r in load_rules_from_files(("pii-hardcoded.yaml",))}


def hits(line: str) -> set[str]:
    return {rid for rid, rule in RULES.items() if rule.pattern.search(line)}


def test_pack_loads_with_guidance_and_is_opt_in() -> None:
    assert set(RULES) == {
        "pii-hardcoded-email",
        "pii-hardcoded-phone",
        "pii-hardcoded-ssn",
        "pii-hardcoded-uk-nino",
        "pii-hardcoded-name",
        "pii-hardcoded-address",
    }
    assert all(r.fix_guidance for r in RULES.values())
    assert "pii-hardcoded.yaml" not in RULE_FILES  # only `argus scan pii` loads it


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ('email = "maria.gonzalez@gmail.com"', "pii-hardcoded-email"),
        ('{"email": "j.okafor@acme-corp.co.uk"}', "pii-hardcoded-email"),
        ("  emailAddress: 'p.nguyen@hospital.org'", "pii-hardcoded-email"),
        ("'email' => 'tom.baker@outlook.com',", "pii-hardcoded-email"),
        ('phone = "+44 7700 912345"', "pii-hardcoded-phone"),
        ('"phoneNumber": "(415) 867-2309"', "pii-hardcoded-phone"),
        ('ssn = "219-09-9999"', "pii-hardcoded-ssn"),
        ("national_insurance = 'JG 10 32 87 B'", "pii-hardcoded-uk-nino"),
        ('first_name = "Margaret"', "pii-hardcoded-name"),
        ('"fullName": "Oluwaseun Adebayo"', "pii-hardcoded-name"),
        ('address = "1428 Elm Street, Springfield, IL 62704"', "pii-hardcoded-address"),
        ("addr = '221 Baker Street, London NW1 6XE'", "pii-hardcoded-address"),
    ],
)
def test_real_looking_values_are_flagged(line: str, rule: str) -> None:
    assert rule in hits(line)


@pytest.mark.parametrize(
    "line",
    [
        'email = "jane.doe@example.com"',
        'email = "dev@api.test"',
        'email = "support@acme.com"',
        'email = "noreply@company.io"',
        "email = get_email(user)",
        'phone = "+1 202-555-0123"',
        'phone = "1234"',
        'ssn = "123-45-6789"',
        'ssn = "078-05-1120"',
        'ssn = "000-12-3456"',
        'ssn = "900-12-3456"',
        'date = "2026-11-24"',
        "nino = 'GB 12 34 56 A'",
        "nino = 'QQ 12 34 56 C'",  # HMRC specimen prefix
        'first_name = "John"',
        'last_name = "Doe"',
        'first_name = form.cleaned_data["first_name"]',
        'address = "123 Main"',
        "@ApiPropertyOptional({ nullable: true, example: '14 Harehills Lane, Leeds LS9 7EW' })",
        "  example: 'maria.gonzalez@gmail.com',",
        "firstName: 'Deleted',",
    ],
)
def test_fake_reserved_and_non_literal_values_are_ignored(line: str) -> None:
    assert hits(line) == set()
