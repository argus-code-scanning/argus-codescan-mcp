"""JWT rules: PyJWT / python-jose, jsonwebtoken, jjwt and golang-jwt."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

JWT_RULES = {
    "python-jwt-verify-disabled",
    "python-jwt-alg-none",
    "js-jwt-decode-unverified",
    "js-jwt-alg-none",
    "js-jwt-ignore-expiration",
    "java-jjwt-unsigned-parse",
    "go-jwt-none-allowed",
    "go-jwt-parse-unverified",
}


def _findings(tmp_path: Path, filename: str, code: str) -> dict[str, str]:
    path = tmp_path / filename
    path.write_text(code)
    return {
        f.rule_id: str(f.severity.value)
        for f in scan_directory(tmp_path).findings
        if f.rule_id in JWT_RULES
    }


def test_rule_pack_is_registered_and_complete() -> None:
    assert "auth-jwt.yaml" in RULE_FILES
    rules = load_rules_from_files(("auth-jwt.yaml",))
    assert {r.id for r in rules} == JWT_RULES
    for rule in rules:
        assert rule.fix_guidance, f"{rule.id} needs fix_guidance"


@pytest.mark.parametrize(
    ("filename", "code", "rule", "severity"),
    [
        # PyJWT / python-jose
        (
            "auth.py",
            'claims = jwt.decode(token, options={"verify_signature": False})',
            "python-jwt-verify-disabled",
            "high",
        ),
        (
            "auth.py",
            "claims = jwt.decode(token, key, verify=False)",
            "python-jwt-verify-disabled",
            "high",
        ),
        (
            "auth.py",
            "claims = jwt.get_unverified_claims(token)",
            "python-jwt-verify-disabled",
            "high",
        ),
        (
            "auth.py",
            'claims = jwt.decode(token, key, algorithms=["HS256", "none"])',
            "python-jwt-alg-none",
            "critical",
        ),
        (
            "auth.py",
            'token = jwt.encode(payload, None, algorithm="none")',
            "python-jwt-alg-none",
            "critical",
        ),
        # jsonwebtoken (Node)
        ("auth.js", "const claims = jwt.decode(token);", "js-jwt-decode-unverified", "high"),
        (
            "auth.ts",
            "const claims = jwt.decode(token, { complete: true });",
            "js-jwt-decode-unverified",
            "high",
        ),
        (
            "auth.js",
            "jwt.verify(token, key, { algorithms: ['none'] });",
            "js-jwt-alg-none",
            "critical",
        ),
        (
            "auth.js",
            'jwt.verify(token, key, { algorithms: ["RS256", "None"] });',
            "js-jwt-alg-none",
            "critical",
        ),
        (
            "auth.js",
            "jwt.verify(token, key, { ignoreExpiration: true });",
            "js-jwt-ignore-expiration",
            "high",
        ),
        # jjwt (Java)
        (
            "Auth.java",
            "Claims c = Jwts.parser().build().parseClaimsJwt(token).getBody();",
            "java-jjwt-unsigned-parse",
            "high",
        ),
        (
            "Auth.java",
            "var c = Jwts.parser().build().parseUnsecuredClaims(token);",
            "java-jjwt-unsigned-parse",
            "high",
        ),
        # golang-jwt
        (
            "auth.go",
            "token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)",
            "go-jwt-none-allowed",
            "critical",
        ),
        ("auth.go", "key := jwt.UnsafeAllowNoneSignatureType", "go-jwt-none-allowed", "critical"),
        (
            "auth.go",
            "token, _, err := parser.ParseUnverified(raw, claims)",
            "go-jwt-parse-unverified",
            "high",
        ),
    ],
)
def test_vulnerable_code_is_flagged(
    tmp_path: Path, filename: str, code: str, rule: str, severity: str
) -> None:
    found = _findings(tmp_path, filename, f"{code}\n")
    assert rule in found
    assert found[rule] == severity


@pytest.mark.parametrize(
    ("filename", "code"),
    [
        ("auth.py", 'claims = jwt.decode(token, key, algorithms=["RS256"])'),
        (
            "auth.py",
            'claims = jwt.decode(token, key, algorithms=["HS256"], options={"require": ["exp"]})',
        ),
        ("auth.py", "header = jwt.get_unverified_header(token)"),
        ("auth.js", "jwt.verify(token, key, { algorithms: ['RS256'] });"),
        ("auth.js", "jwt.verify(token, key, { ignoreExpiration: false });"),
        ("auth.ts", "const claims = jwt.verify(token, key);"),
        ("Auth.java", "Claims c = Jwts.parser().verifyWith(key).build().parseSignedClaims(t);"),
        (
            "Auth.java",
            "Claims c = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();",
        ),
        (
            "auth.go",
            'token, err := jwt.Parse(raw, keyFunc, jwt.WithValidMethods([]string{"RS256"}))',
        ),
        ("auth.go", "token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)"),
    ],
)
def test_safe_code_is_not_flagged(tmp_path: Path, filename: str, code: str) -> None:
    assert _findings(tmp_path, filename, f"{code}\n") == {}


def test_rules_only_apply_to_their_own_language(tmp_path: Path) -> None:
    # Python's verified jwt.decode must not trigger the Node jwt.decode rule, and an unverified
    # decode in a .py file is reported by the Python rule only. Each case gets its own folder.
    cases = {
        "verified_py": ("ok.py", 'jwt.decode(token, key, algorithms=["RS256"])\n'),
        "unverified_py": ("bad.py", 'jwt.decode(token, options={"verify_signature": False})\n'),
        "text_file": ("notes.txt", "jwt.decode(token)\n"),
    }
    results = {}
    for name, (filename, code) in cases.items():
        folder = tmp_path / name
        folder.mkdir()
        results[name] = set(_findings(folder, filename, code))
    assert results["verified_py"] == set()
    assert results["unverified_py"] == {"python-jwt-verify-disabled"}
    assert results["text_file"] == set()
