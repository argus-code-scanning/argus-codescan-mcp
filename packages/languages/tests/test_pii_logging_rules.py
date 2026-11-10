"""PII in logs, prints, exceptions and third-party error trackers (#62)."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def _rules(tmp_path: Path, name: str, line: str) -> set[str]:
    path = tmp_path / name
    path.write_text(line + "\n")
    return {f.rule_id for f in scan_path(path, rules=load_rules_from_files(("pii.yaml",))).findings}


@pytest.mark.parametrize(
    ("name", "line", "rule"),
    [
        # Issue examples
        ("a.py", 'logger.error(f"Failed for user {user.email}")', "pii-email-in-logs"),
        ("a.py", 'sentry_sdk.set_user({"email": request.user.email})', "pii-third-party-context"),
        ("a.py", 'print(f"SSN: {ssn}")', "pii-print-debug"),
        ("a.py", "log.exception(str(request.form))", "pii-request-dump-in-logs"),
        # Python
        ("a.py", 'self.logger.info("user %s", user.phone_number)', "pii-in-logs"),
        ("a.py", "logging.warning('dob=%s', dob)", "pii-in-logs"),
        ("a.py", 'logger.info("lookup %s", data["ssn"])', "pii-in-logs"),
        ("a.py", 'raise ValueError(f"No account for {user.email}")', "pii-exception-message"),
        ("a.py", 'logger.debug("payload %s", request.get_json())', "pii-request-dump-in-logs"),
        # JavaScript / TypeScript
        ("a.js", "console.log(`Welcome ${user.firstName}`)", "pii-in-logs"),
        ("a.ts", "logger.info('signup', { email: user.email })", "pii-email-in-logs"),
        ("a.js", "throw new Error(`Duplicate phone ${phone}`)", "pii-exception-message"),
        ("a.js", "console.error('bad request', req.body)", "pii-request-dump-in-logs"),
        ("a.ts", "Sentry.setUser({ id: u.id, email: u.email })", "pii-third-party-context"),
        # Java
        ("A.java", 'logger.info("User {}", user.getEmail());', "pii-email-in-logs"),
        ("A.java", 'log.warn("SSN mismatch for {}", customer.getSsn());', "pii-in-logs"),
        ("A.java", "System.out.println(user.getLastName());", "pii-print-debug"),
        (
            "A.java",
            'throw new IllegalStateException("bad dob " + person.getDateOfBirth());',
            "pii-exception-message",
        ),
        # Go
        ("a.go", 'log.Printf("login %s", u.Email)', "pii-email-in-logs"),
        ("a.go", 'slog.Info("signup", "phone", u.Phone)', "pii-in-logs"),
        ("a.go", 'fmt.Println("user", u.FullName)', "pii-print-debug"),
        ("a.go", 'return fmt.Errorf("no user with email %s", u.Email)', "pii-exception-message"),
    ],
)
def test_pii_leaks_are_flagged(tmp_path: Path, name: str, line: str, rule: str) -> None:
    assert rule in _rules(tmp_path, name, line)


@pytest.mark.parametrize(
    ("name", "line"),
    [
        # PII words in plain message text, not values
        ("a.py", 'logger.info("Sending email to user")'),
        ("a.py", 'logger.info("Reset link sent, email delivered")'),
        ("a.py", 'logger.warning("Phone verification failed for user %s", user.id)'),
        ("a.js", "console.log('Enter your first name and phone number')"),
        ("A.java", 'logger.info("Updated user {}", user.getId());'),
        ("a.go", 'log.Printf("sent email to user %d", u.ID)'),
        # Safe patterns
        ("a.py", 'logger.info("login", extra={"user_id": user.id})'),
        ("a.py", "logger.info('name=%s', request.form['username'])"),
        ("a.py", "logger.info('source=%s', request.args.get('utm_source'))"),
        ("a.js", "console.log('page', req.query.page)"),
        ("a.py", 'sentry_sdk.set_user({"id": user.id})'),
        ("a.py", 'raise ValueError(f"No account for id {user.id}")'),
        ("a.py", "fingerprint(patient_record)"),
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, name: str, line: str) -> None:
    assert _rules(tmp_path, name, line) == set()


def test_hipaa_rule_no_longer_double_flags_pii(tmp_path: Path) -> None:
    rules = _rules(tmp_path, "a.py", 'logger.info("ssn %s", ssn)')
    assert rules == {"pii-in-logs"}
    assert "hipaa-phi-in-logs" in _rules(tmp_path, "b.py", 'logger.info("dx %s", diagnosis)')


def test_findings_carry_fix_guidance_and_classification(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('logger.error(f"Failed for user {user.email}")\n')

    finding = next(f for f in scan_directory(tmp_path).findings if f.rule_id == "pii-email-in-logs")

    assert finding.data_classification == "pii"
    assert "stable user id" in finding.fix_guidance
    assert finding.to_dict()["fix_guidance"] == finding.fix_guidance
