"""Rule noise found running `argus scan vibe` on public AI-built apps (#273)."""

from __future__ import annotations

from pathlib import Path

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path

GRANT = next(r for r in load_rules_from_files(("other.yaml",)) if r.id == "sql-grant-all")


def test_supabase_server_role_grants_are_not_flagged() -> None:
    assert not GRANT.pattern.search("grant all on public.profiles to service_role;")
    assert not GRANT.pattern.search("GRANT ALL ON TABLE public.x TO postgres;")
    assert GRANT.pattern.search("grant all on public.profiles to anon;")
    assert GRANT.pattern.search("grant all on public.x to service_role, anon;")


def test_shadcn_chart_style_is_low_confidence(tmp_path: Path) -> None:
    chart = tmp_path / "chart.tsx"
    chart.write_text(
        "return (\n  <style\n    dangerouslySetInnerHTML={{\n"
        "      __html: Object.entries(THEMES).map(([t, p]) => `${p} {}`).join(''),\n"
        "    }}\n  />\n)\n"
    )
    user = tmp_path / "post.tsx"
    user.write_text("<div dangerouslySetInnerHTML={{ __html: post.body }} />\n")
    result = scan_path(str(tmp_path))
    found = {
        (Path(f.file).name, f.confidence) for f in result.findings if f.rule_id == "xss-innerhtml"
    }
    assert ("chart.tsx", "low") in found
    assert any(name == "post.tsx" and conf != "low" for name, conf in found)
