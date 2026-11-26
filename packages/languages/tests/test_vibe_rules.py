"""Line rules for AI-built apps (#272)."""

from __future__ import annotations

import base64
import json

import pytest

from argus_languages.rules_loader import RULE_FILES, load_rules_from_files

RULES = {r.id: r for r in load_rules_from_files(("vibe.yaml",))}


def _jwt(role: str) -> str:
    """A Supabase-shaped JWT (dummy signature) carrying ``role``."""
    claims = {"iss": "supabase", "ref": "abcdefghijklmnop", "role": role, "iat": 1700000000}
    payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
    return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload.decode().rstrip('=')}.c2lnbmF0dXJl"


SERVICE_KEY = _jwt("service_role")
ANON_KEY = _jwt("anon")


def hits(text: str) -> set[str]:
    return {rid for rid, r in RULES.items() if r.pattern.search(text)}


def test_registered_with_guidance() -> None:
    assert "vibe.yaml" in RULE_FILES
    assert all(r.fix_guidance for r in RULES.values())


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;", "vibe-public-env-secret"),
        ("const k = import.meta.env.VITE_STRIPE_SECRET_KEY", "vibe-public-env-secret"),
        ("REACT_APP_SUPABASE_SERVICE_ROLE_KEY", "vibe-public-env-secret"),
        ("EXPO_PUBLIC_ANTHROPIC_KEY", "vibe-public-env-secret"),
        (
            "const openai = new OpenAI({ apiKey, dangerouslyAllowBrowser: true });",
            "vibe-llm-key-in-browser",
        ),
        (f'const supabase = createClient(url, "{SERVICE_KEY}")', "vibe-supabase-service-role-key"),
        ("localStorage.setItem('access_token', data.token)", "vibe-token-in-localstorage"),
        (
            'create policy "edit" on public.profiles\n  for update\n  using (true);',
            "vibe-supabase-policy-allows-all",
        ),
        ("alter table public.orders disable row level security;", "vibe-supabase-rls-disabled"),
    ],
)
def test_flags(text: str, rule: str) -> None:
    assert rule in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "process.env.NEXT_PUBLIC_SUPABASE_URL",
        "process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
        "process.env.OPENAI_API_KEY",  # server-only name
        "import.meta.env.VITE_FIREBASE_API_KEY",  # Firebase web keys are public by design
        f'createClient(url, "{ANON_KEY}")',
        "localStorage.setItem('theme', 'dark')",
        # public reads can be intended
        'create policy "read" on public.posts for select using (true);',
        'create policy "own" on public.profiles for update using (auth.uid() = id);',
        "alter table public.orders enable row level security;",
    ],
)
def test_safe(text: str) -> None:
    assert hits(text) == set()


def test_policy_rules_by_role() -> None:
    """Found tuning on public AI-built apps: who a (true) policy applies to sets the risk."""
    anyone = 'create policy "w" on public.notes for insert with check (true);'
    signed_in = (
        'CREATE POLICY "audit" ON public.audit FOR INSERT TO authenticated WITH CHECK (true);'
    )
    service = 'create policy "svc" on public.jobs for all to service_role using (true);'
    owner_but_open_check = (
        'CREATE POLICY "s" ON public.sessions\n  FOR ALL\n  TO authenticated\n'
        "  USING (auth.uid() = user_id)\n  WITH CHECK (true);"
    )
    assert "vibe-supabase-policy-allows-all" in hits(anyone)
    assert hits(signed_in) == {"vibe-supabase-policy-any-user"}
    assert hits(owner_but_open_check) == {"vibe-supabase-policy-any-user"}
    assert not hits(service)


def test_reads_all_only_for_private_tables() -> None:
    orders = 'create policy "r" on public.orders for select to authenticated using (true);'
    profiles = 'create policy "r" on public.profiles for select using (true);'
    products = 'create policy "r" on public.products for select to authenticated using (true);'
    own = 'create policy "r" on public.orders for select using (auth.uid() = user_id);'
    assert hits(orders) == {"vibe-supabase-policy-reads-all"}
    assert hits(profiles) == {"vibe-supabase-policy-reads-all"}
    assert not hits(products)
    assert not hits(own)
