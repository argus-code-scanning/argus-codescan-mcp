"""Project-level checks for AI-built apps (#272)."""

from __future__ import annotations

from pathlib import Path

from argus.tools.vibe_checks import vibe_findings


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def by_rule(root: Path) -> dict[str, list[tuple[str, int]]]:
    out: dict[str, list[tuple[str, int]]] = {}
    for f in vibe_findings(str(root))[0]:
        out.setdefault(f.rule_id, []).append((f.file, f.line))
    return out


LOVABLE_APP = {
    "package.json": '{"dependencies": {"next": "15", "@supabase/supabase-js": "^2"}}',
    ".env.local": "NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=eyJanon\nNEXT_PUBLIC_OPENAI_API_KEY=sk-proj-abc123\nOPENAI_API_KEY=sk-proj-server\n",
    ".env.example": "NEXT_PUBLIC_OPENAI_API_KEY=your-key-here\n",
    "supabase/migrations/001_init.sql": (
        "create table public.profiles (id uuid primary key, email text);\n"
        "alter table public.profiles enable row level security;\n"
        "create table public.orders (id serial primary key, user_id uuid, total int);\n"
        "create table if not exists private.audit (id int);\n"
    ),
    "app/admin/page.tsx": "'use client'\nimport { createClient } from '@supabase/supabase-js'\nconst s = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)\n",
    "app/api/orders/route.ts": (
        "import { supabase } from '@/lib/supabase'\n"
        "export async function DELETE(req: Request) {\n"
        "  const { id } = await req.json()\n"
        "  await supabase.from('orders').delete().eq('id', id)\n"
        "  return Response.json({ ok: true })\n"
        "}\n"
    ),
    "app/api/profile/route.ts": (
        "import { auth } from '@/auth'\n"
        "export async function POST(req: Request) {\n"
        "  const session = await auth()\n"
        "  if (!session) return new Response('Unauthorized', { status: 401 })\n"
        "  await db.update(profiles).set({ name })\n"
        "}\n"
    ),
    "app/actions.ts": "'use server'\nexport async function deletePost(id: string) {\n  await prisma.post.delete({ where: { id } })\n}\n",
    "app/api/stripe/webhook/route.ts": "export async function POST(req) {\n  const event = stripe.webhooks.constructEvent(body, sig, secret)\n  await db.insert(payments).values(x)\n}\n",
}


def test_lovable_style_app(tmp_path: Path) -> None:
    found = by_rule(write(tmp_path, LOVABLE_APP))
    assert found["vibe-public-env-secret"] == [
        (".env.local", 3)
    ]  # not the anon key, not .env.example
    assert found["vibe-supabase-table-without-rls"] == [
        ("supabase/migrations/001_init.sql", 3)
    ]  # orders only
    assert found["vibe-supabase-service-role-in-browser"] == [("app/admin/page.tsx", 3)]
    assert sorted(found["vibe-unprotected-mutation"]) == [
        ("app/actions.ts", 2),
        ("app/api/orders/route.ts", 2),
    ]


def test_secret_values_are_never_printed(tmp_path: Path) -> None:
    findings, _ = vibe_findings(str(write(tmp_path, LOVABLE_APP)))
    text = " ".join(f"{f.title} {f.description}" for f in findings)
    assert "sk-proj" not in text


def test_middleware_auth_lowers_confidence(tmp_path: Path) -> None:
    write(tmp_path, {**LOVABLE_APP, "middleware.ts": "export default clerkMiddleware()\n"})
    findings, meta = vibe_findings(str(tmp_path))
    mut = [f for f in findings if f.rule_id == "vibe-unprotected-mutation"]
    assert mut and all(f.confidence == "low" for f in mut)
    assert meta["middleware_auth"] == "middleware.ts"


def test_firebase_rules(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "firebase.json": "{}",
            "firestore.rules": "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{doc=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
            "storage.rules": "match /b/{bucket}/o {\n  allow read, write: if request.time < timestamp.date(2026, 12, 1);\n}\n",
            "database.rules.json": '{"rules": {".read": true, ".write": "auth != null"}}',
        },
    )
    found = by_rule(tmp_path)
    assert found["vibe-firebase-rules-open"] == [
        ("firestore.rules", 5),
        ("database.rules.json", 1),
    ] or sorted(found["vibe-firebase-rules-open"]) == sorted(
        [("firestore.rules", 5), ("database.rules.json", 1)]
    )
    assert found["vibe-firebase-test-mode"] == [("storage.rules", 2)]


def test_safe_firebase_rules(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "firestore.rules": "match /users/{uid} {\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}\n",
        },
    )
    assert by_rule(tmp_path) == {}


def test_python_endpoints(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "api/open.py": "@app.post('/items')\ndef add(item: Item, db=Depends(get_db)):\n    db.add(Item(**item.dict()))\n    db.commit()\n",
            "api/safe.py": "@app.post('/items')\ndef add(item: Item, user=Depends(get_current_user)):\n    db.add(item)\n    db.commit()\n",
        },
    )
    assert by_rule(tmp_path) == {"vibe-unprotected-mutation": [("api/open.py", 1)]}


def test_no_stack_no_findings(tmp_path: Path) -> None:
    write(
        tmp_path, {"schema.sql": "create table public.t (id int);\n", "app.js": "console.log(1)\n"}
    )
    assert by_rule(tmp_path) == {}  # plain SQL without Supabase isn't about RLS


def test_rls_enabled_by_a_loop_over_pg_tables(tmp_path: Path) -> None:
    """A loop over pg_tables covers tables made before it, not tables made in later files."""
    write(
        tmp_path,
        {
            "supabase/config.toml": "",
            "supabase/migrations/001_init.sql": (
                "create table public.clients (id int);\ncreate table public.invoices (id int);\n"
                "do $$ declare t text; begin\n"
                "  for t in select tablename from pg_tables where schemaname = 'public' loop\n"
                "    execute format('alter table public.%I enable row level security', t);\n"
                "  end loop; end $$;\n"
                "create table public.after_loop (id int);\n"
            ),
            "supabase/migrations/002_more.sql": "create table public.later (id int);\n",
        },
    )
    tables = {
        f.title.split()[1]
        for f in vibe_findings(str(tmp_path))[0]
        if f.rule_id == "vibe-supabase-table-without-rls"
    }
    assert tables == {"after_loop", "later"}


def test_server_only_files_are_not_browser_code(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": '{"dependencies": {"vite": "5", "@supabase/supabase-js": "^2"}}',
            "src/integrations/supabase/client.server.ts": "createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)\n",
            "supabase/functions/admin/index.ts": "createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))\n",
            "src/pages/Admin.tsx": "createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n",
        },
    )
    assert by_rule(tmp_path)["vibe-supabase-service-role-in-browser"] == [
        ("src/pages/Admin.tsx", 1)
    ]
