from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
    "__pycache__", "target", "bin", "obj", ".venv", "venv", ".terraform",
    ".idea", ".vscode", "Pods", "DerivedData", ".dart_tool", ".pub-cache",
    ".gradle",
}

# Flutter platform folders under android/ are scanned; skip build artifacts only
FLUTTER_SKIP_DIR_NAMES = {".gradle", "build", "Pods", "DerivedData"}

GENERATED_DART_SUFFIXES = (".g.dart", ".freezed.dart", ".gr.dart", ".mocks.dart")

LanguageId = str

EXT_MAP: dict[str, LanguageId] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".py": "python", ".pyw": "python",
    ".java": "java", ".jsp": "java",
    ".php": "php", ".phtml": "php",
    ".go": "go",
    ".rb": "ruby", ".erb": "ruby",
    ".cs": "csharp",
    ".rs": "rust",
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "terraform",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".sql": "sql",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".pl": "perl", ".pm": "perl",
    ".lua": "lua",
    ".ex": "elixir", ".exs": "elixir",
    ".vue": "vue",
    ".dart": "dart",
}

ANSIBLE_PATH_MARKERS = (
    "/roles/", "/playbooks/", "/tasks/", "/handlers/", "/vars/", "/defaults/",
    "/group_vars/", "/host_vars/", "/inventory/",
)


@dataclass
class ScannedFile:
    path: Path
    relative: str
    language: LanguageId


def _is_ansible_yaml(rel: str, content: str) -> bool:
    lower = rel.lower()
    if any(m in lower for m in ANSIBLE_PATH_MARKERS):
        return True
    if re.search(r"ansible\.builtin|ansible\.legacy|- hosts:|become:|gather_facts:", content):
        return True
    return "playbook" in Path(lower).name


def _is_kubernetes_yaml(rel: str, content: str) -> bool:
    lower = rel.lower()
    if any(p in lower for p in ("/k8s/", "/kubernetes/", "/manifests/")):
        return True
    return bool(re.search(r"^\s*apiVersion:", content, re.M) and re.search(r"^\s*kind:", content, re.M))


def _is_flutter_pubspec(name: str, content: str) -> bool:
    if name != "pubspec.yaml":
        return False
    return "dependencies:" in content or "flutter:" in content


def _is_generated_dart(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in GENERATED_DART_SUFFIXES)


def classify_file(path: Path, root: Path, content: str) -> LanguageId | None:
    rel = str(path.relative_to(root))
    name = path.name.lower()

    if _is_generated_dart(name):
        return None

    if name == "androidmanifest.xml":
        return "flutter"
    if name == "info.plist" and ("ios" in rel.lower() or "macos" in rel.lower() or "CFBundle" in content):
        return "flutter"
    if _is_flutter_pubspec(name, content):
        return "flutter"

    if name == "dockerfile" or name.endswith(".dockerfile"):
        return "docker"
    if name.startswith("docker-compose") and name.endswith((".yml", ".yaml")):
        return "docker"

    ext = path.suffix.lower()
    if ext in (".yaml", ".yml"):
        if _is_ansible_yaml(rel, content):
            return "ansible"
        if _is_kubernetes_yaml(rel, content):
            return "kubernetes"
        return None

    if ext == ".json" and _is_kubernetes_yaml(rel, content):
        return "kubernetes"

    return EXT_MAP.get(ext)


def discover_files(target: Path) -> list[ScannedFile]:
    root = target if target.is_dir() else target.parent
    out: list[ScannedFile] = []

    def should_skip_dir(entry: Path, name: str) -> bool:
        if name in SKIP_DIRS:
            return True
        if name.startswith("."):
            return True
        # Keep android/ but skip nested Gradle build dirs
        if name in FLUTTER_SKIP_DIR_NAMES and "android" in str(entry).lower():
            return True
        return False

    def walk(directory: Path, depth: int) -> None:
        if depth > 16:
            return
        try:
            entries = list(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if should_skip_dir(entry, entry.name):
                continue
            if entry.is_dir():
                walk(entry, depth + 1)
                continue
            try:
                content = entry.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            language = classify_file(entry, root, content)
            if not language:
                continue
            out.append(
                ScannedFile(
                    path=entry,
                    relative=str(entry.relative_to(root)),
                    language=language,
                )
            )

    if target.is_file():
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        language = classify_file(target, root, content)
        if language:
            out.append(ScannedFile(path=target, relative=target.name, language=language))
    else:
        walk(target, 0)

    return out


SUPPORTED_LANGUAGES = sorted(
    set(EXT_MAP.values())
    | {"terraform", "ansible", "docker", "kubernetes", "shell", "sql", "flutter", "dart"}
)
