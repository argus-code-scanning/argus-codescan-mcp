"""`argus unit-test` / MCP check_unit_tests (#276)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import cli
from argus.tools.testing_checks import find_testing_gaps

ROUTE = (
    "export async function DELETE(req: Request) {\n"
    "  await supabase.from('orders').delete().eq('id', id)\n}\n"
)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def rules(root: Path) -> dict[str, list[tuple[str, int]]]:
    out: dict[str, list[tuple[str, int]]] = {}
    for f in find_testing_gaps(str(root))[0]:
        out.setdefault(f.rule_id, []).append((f.file, f.line))
    return out


UNTESTED_APP = {
    "package.json": json.dumps(
        {
            "scripts": {"test": 'echo "Error: no test specified" && exit 1'},
            "dependencies": {"next": "15"},
        },
        indent=2,
    ),
    "app/api/orders/route.ts": ROUTE,
    "app/login/page.tsx": "export default function Login() { return null }\n",
    "app/page.tsx": "export default function Home() { return null }\n",
    "lib/util.ts": "export const x = 1\n",
}


def test_untested_app(tmp_path: Path) -> None:
    found = rules(write(tmp_path, UNTESTED_APP))
    assert found["tests-placeholder-script"] == [("package.json", 3)]
    assert found["tests-none"] == [("package.json", 0)]
    assert found["tests-untested-mutation"] == [("app/api/orders/route.ts", 1)]
    assert found["tests-no-e2e"] == [("app/login/page.tsx", 0)]


def test_well_tested_app(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "scripts": {"test": "vitest run"},
                    "devDependencies": {"vitest": "2", "@playwright/test": "1"},
                }
            ),
            "app/api/orders/route.ts": ROUTE,
            "app/login/page.tsx": "export default function Login() { return null }\n",
            "tests/orders.test.ts": "it('rejects anonymous', () => { expect(1).toBe(1) })\n",
            ".github/workflows/ci.yml": "steps:\n  - run: npm ci && npm test\n",
        },
    )
    assert rules(tmp_path) == {}


def test_test_quality(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"devDependencies": {"jest": "29"}}',
            "src/a.test.ts": "test('runs', () => { doThing() })\n",
            "src/b.test.ts": "describe.only('x', () => { it('y', () => expect(1).toBe(1)) })\n",
            "src/c.test.ts": "it.skip('flaky', () => { expect(1).toBe(2) })\n",
            "tests/test_api.py": "def test_add():\n    add(1, 2)\n",
            ".github/workflows/deploy.yml": "steps:\n  - run: npm run build\n",
        },
    )
    found = rules(tmp_path)
    assert sorted(found["tests-no-assertions"]) == [("src/a.test.ts", 1), ("tests/test_api.py", 1)]
    assert found["tests-focused"] == [("src/b.test.ts", 1)]
    assert found["tests-skipped"] == [("src/c.test.ts", 1)]
    assert found["tests-not-in-ci"] == [(".github/workflows/deploy.yml", 0)]


def test_mutation_counts_as_tested_when_a_test_mentions_it(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"scripts": {"test": "node --test"}}',
            "app/api/orders/route.ts": ROUTE,
            "app/api/invoices/route.ts": ROUTE.replace("orders", "invoices"),
            "tests/orders.test.ts": "import { DELETE } from '../app/api/orders/route'\n"
            "it('x', () => { expect(DELETE).toBeDefined() })\n",
        },
    )
    found = rules(tmp_path)
    assert found["tests-untested-mutation"] == [("app/api/invoices/route.ts", 1)]
    assert "tests-no-runner" not in found  # node --test is a runner


def test_python_project(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname='x'\n[dependency-groups]\ndev=['pytest']\n",
            "app/main.py": "@app.post('/items')\ndef add(item):\n    db.add(item)\n    db.commit()\n",
            "tests/test_main.py": "def test_add():\n    assert add_item() == 1\n",
        },
    )
    assert rules(tmp_path) == {"tests-untested-mutation": [("app/main.py", 1)]}


def test_not_an_app(tmp_path: Path) -> None:
    write(tmp_path, {"notes.md": "# hi\n", "script.sh": "echo hi\n"})
    assert find_testing_gaps(str(tmp_path)) == ([], {"app": False})


def test_dto_named_login_is_not_a_page(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"devDependencies": {"jest": "29"}}',
            "src/auth/dto/login.dto.ts": "export class LoginDto {}\n",
            "src/app.spec.ts": "it('x', () => expect(1).toBe(1))\n",
        },
    )
    assert "tests-no-e2e" not in rules(tmp_path)


def test_cli_unit_test(tmp_path: Path, capsys) -> None:
    write(tmp_path, UNTESTED_APP)
    code = cli.main(["unit-test", str(tmp_path), "--fail-under", "50"])
    out = capsys.readouterr().out
    assert "Testing score: 10/100. No real tests." in out
    assert "Prompt to write the tests" in out
    assert "Set up vitest first" in out
    assert code == 1
    assert cli.main(["unit-test", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["testing"]["score"] == 10
    assert {i["rule_id"] for i in data["testing"]["items"]} >= {"tests-none"}


def test_vibe_scan_does_not_include_tests(tmp_path: Path, capsys) -> None:
    write(tmp_path, UNTESTED_APP)
    cli.main(["scan", "vibe", str(tmp_path), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert not any(i["rule_id"].startswith("tests-") for i in data["vibe"]["items"])


@pytest.mark.asyncio
async def test_mcp_check_unit_tests(tmp_path: Path) -> None:
    from argus.server import _handle_check_unit_tests

    write(tmp_path, UNTESTED_APP)
    out = await _handle_check_unit_tests({"target": str(tmp_path)})
    assert "Testing score:" in out[0].text
    data = json.loads(
        (await _handle_check_unit_tests({"target": str(tmp_path), "format": "json"}))[0].text
    )
    assert data["score"] == 10
