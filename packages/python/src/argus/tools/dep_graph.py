"""How each dependency gets into a project, read from its lockfile.

For every supported lockfile this returns the direct dependencies, the dev-only ones and, where
the format records it, which package depends on which. From that, ``paths_to`` gives the install
paths for a vulnerable package ("typeorm › tinyglobby › picomatch"), runtime paths first, and
``is_dev_only`` tells whether it only arrives through dev dependencies.

Formats without a graph still give direct / dev information (pubspec.lock, requirements.txt).
Everything is read from files; nothing is installed or resolved. Go uses ``go mod graph`` when
Go is installed (with the module proxy switched off, so it never downloads).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]

ARROW = " \u203a "
_MAX_PATHS = 20
_MAX_DEPTH = 10


@dataclass
class DependencyGraph:
    direct: set[str] = field(default_factory=set)
    # Packages the lockfile itself marks dev-only (npm "dev": true, composer packages-dev, ...).
    dev: set[str] = field(default_factory=set)
    # Direct dependencies declared as dev dependencies.
    dev_direct: set[str] = field(default_factory=set)
    edges: dict[str, set[str]] = field(default_factory=dict)

    def add_edge(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.setdefault(parent, set()).add(child)

    def paths_to(self, name: str) -> list[str]:
        """Install paths from a direct dependency down to ``name``, runtime paths first."""
        if not self.edges:
            return [name] if name in self.direct else []
        parents: dict[str, set[str]] = {}
        for parent, children in self.edges.items():
            for child in children:
                parents.setdefault(child, set()).add(parent)
        found: list[list[str]] = []
        queue: deque[list[str]] = deque([[name]])
        reached: set[str] = set()
        while queue and len(found) < _MAX_PATHS:
            chain = queue.popleft()
            head = chain[0]
            if head in self.direct and head not in reached:
                reached.add(head)
                found.append(chain)
            if len(chain) >= _MAX_DEPTH:
                continue
            for parent in sorted(parents.get(head, ())):
                if parent not in chain:
                    queue.append([parent, *chain])
        found.sort(key=lambda c: (c[0] in self.dev_direct, len(c), c[0]))
        return [ARROW.join(chain) for chain in found]

    def is_dev_only(self, name: str) -> bool:
        if name in self.dev:
            return True
        if name in self.direct:
            return name in self.dev_direct
        paths = self.paths_to(name)
        return bool(paths) and all(p.split(ARROW)[0] in self.dev_direct for p in paths)


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_toml(path: Path) -> dict[str, Any]:
    if _toml is None:
        return {}
    try:
        return _toml.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _package_json_direct(lockfile: Path, graph: DependencyGraph) -> None:
    manifest = _read_json(lockfile.parent / "package.json")
    if not isinstance(manifest, dict):
        return
    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        deps = manifest.get(section)
        if isinstance(deps, dict):
            graph.direct.update(deps)
            if section == "devDependencies":
                graph.dev_direct.update(deps)


def _npm(lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    data = json.loads(text)
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        _package_json_direct(lockfile, graph)
        return graph
    root = packages.get("") or {}
    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        deps = root.get(section)
        if isinstance(deps, dict):
            graph.direct.update(deps)
            if section == "devDependencies":
                graph.dev_direct.update(deps)
    for key, entry in packages.items():
        if "node_modules/" not in key or not isinstance(entry, dict):
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
        if entry.get("dev"):
            graph.dev.add(name)
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            for child in entry.get(section) or {}:
                graph.add_edge(name, child)
    return graph


def _manifest_only_npm(lockfile: Path, _text: str) -> DependencyGraph:
    graph = DependencyGraph()  # yarn.lock / pnpm-lock.yaml: direct and dev from package.json
    _package_json_direct(lockfile, graph)
    return graph


def _go(lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    module = ""
    block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("module "):
            module = line.split()[1]
        if line.startswith("require ("):
            block = True
            continue
        if block and line.startswith(")"):
            block = False
            continue
        if block or line.startswith("require "):
            parts = line.removeprefix("require ").split()
            if len(parts) >= 2 and "// indirect" not in line:
                graph.direct.add(parts[0])
    graph.direct.add("stdlib")
    for parent, child in _go_mod_graph(lockfile.parent):
        graph.add_edge(module if parent == module else parent, child)
    if module:
        graph.direct.discard(module)
    return graph


def _go_mod_graph(directory: Path) -> list[tuple[str, str]]:
    """``go mod graph`` edges (module names without versions); empty when Go is unavailable."""
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOTOOLCHAIN": "local"}
    try:
        proc = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            ["go", "mod", "graph"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    edges = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            edges.append((parts[0].split("@")[0], parts[1].split("@")[0]))
    return edges


def _pubspec(_lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    data = yaml.safe_load(text)
    for name, entry in ((data or {}).get("packages") or {}).items():
        kind = str((entry or {}).get("dependency", ""))
        if kind.startswith("direct"):
            graph.direct.add(name)
        if kind == "direct dev":
            graph.dev_direct.add(name)
    return graph


def _cargo(_lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    if _toml is None:
        return graph
    packages = [p for p in _toml.loads(text).get("package", []) if isinstance(p, dict)]
    members = {p.get("name") for p in packages if not p.get("source")}
    for entry in packages:
        for dep in entry.get("dependencies", []) or []:
            child = str(dep).split()[0]
            if entry.get("name") in members:
                graph.direct.add(child)
            else:
                graph.add_edge(str(entry.get("name")), child)
    return graph


def _python_toml(lockfile: Path, text: str) -> DependencyGraph:
    """poetry.lock / uv.lock edges; direct and dev dependencies from the project itself."""
    graph = DependencyGraph()
    if _toml is None:
        return graph
    for entry in _toml.loads(text).get("package", []):
        if not isinstance(entry, dict):
            continue
        name = _norm_py(str(entry.get("name", "")))
        source = entry.get("source") if isinstance(entry.get("source"), dict) else {}
        deps = entry.get("dependencies") or {}
        children = list(deps) if isinstance(deps, dict) else [d.get("name", "") for d in deps]
        if "virtual" in source or "editable" in source:  # uv: the project itself
            graph.direct.update(_norm_py(c) for c in children)
            for group in (entry.get("dev-dependencies") or {}).values():
                dev = {_norm_py(d.get("name", "")) for d in group if isinstance(d, dict)}
                graph.direct.update(dev)
                graph.dev_direct.update(dev)
            continue
        if entry.get("category") == "dev":  # older poetry
            graph.dev.add(name)
        for child in children:
            graph.add_edge(name, _norm_py(str(child)))
    project = _read_toml(lockfile.parent / "pyproject.toml")
    poetry = (project.get("tool") or {}).get("poetry") or {}
    for dep in poetry.get("dependencies") or {}:
        if dep != "python":
            graph.direct.add(_norm_py(dep))
    for group in (poetry.get("group") or {}).values():
        dev = {_norm_py(d) for d in (group or {}).get("dependencies") or {}}
        graph.direct.update(dev)
        graph.dev_direct.update(dev)
    for spec in (project.get("project") or {}).get("dependencies") or []:
        graph.direct.add(_norm_py(re.split(r"[\s<>=!~;\[(]", spec, maxsplit=1)[0]))
    return graph


def _pipfile(lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    data = json.loads(text)
    graph.dev.update(_norm_py(n) for n in (data.get("develop") or {}))
    graph.dev.difference_update(_norm_py(n) for n in (data.get("default") or {}))
    pipfile = _read_toml(lockfile.parent / "Pipfile")  # direct dependencies
    graph.direct.update(_norm_py(n) for n in pipfile.get("packages") or {})
    dev = {_norm_py(n) for n in pipfile.get("dev-packages") or {}}
    graph.direct.update(dev)
    graph.dev_direct.update(dev)
    return graph


def _composer(lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    data = json.loads(text)
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", ""))
            if section == "packages-dev":
                graph.dev.add(name)
            for child in entry.get("require") or {}:
                if "/" in child:  # skip php / ext-* platform requirements
                    graph.add_edge(name, child)
    manifest = _read_json(lockfile.parent / "composer.json")
    if isinstance(manifest, dict):
        for section in ("require", "require-dev"):
            deps = {d for d in manifest.get(section) or {} if "/" in d}
            graph.direct.update(deps)
            if section == "require-dev":
                graph.dev_direct.update(deps)
    return graph


def _gemfile(_lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    section = ""
    current = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            continue
        if section == "GEM":
            spec = re.match(r"^    ([\w.-]+) \(", line)
            dep = re.match(r"^      ([\w.-]+)", line)
            if spec:
                current = spec.group(1)
            elif dep and current:
                graph.add_edge(current, dep.group(1))
        elif section == "DEPENDENCIES":
            dep = re.match(r"^  ([\w.-]+)", line)
            if dep:
                graph.direct.add(dep.group(1))
    return graph


def _nuget(_lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()
    data = json.loads(text)
    for deps in (data.get("dependencies") or {}).values():
        for name, entry in (deps or {}).items():
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "Direct":
                graph.direct.add(name)
            for child in entry.get("dependencies") or {}:
                graph.add_edge(name, child)
    return graph


def _requirements(_lockfile: Path, text: str) -> DependencyGraph:
    graph = DependencyGraph()  # a requirements file lists what the project installs directly
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line.strip())
        if match:
            graph.direct.add(_norm_py(match.group(1)))
    return graph


_READERS = {
    "package-lock.json": _npm,
    "npm-shrinkwrap.json": _npm,
    "yarn.lock": _manifest_only_npm,
    "pnpm-lock.yaml": _manifest_only_npm,
    "go.mod": _go,
    "pubspec.lock": _pubspec,
    "Cargo.lock": _cargo,
    "poetry.lock": _python_toml,
    "uv.lock": _python_toml,
    "Pipfile.lock": _pipfile,
    "composer.lock": _composer,
    "Gemfile.lock": _gemfile,
    "gems.locked": _gemfile,
    "packages.lock.json": _nuget,
}


def read_graph(lockfile: Path) -> DependencyGraph:
    """The dependency graph of one lockfile; an empty graph when it can't be read."""
    reader = _READERS.get(lockfile.name)
    if reader is None and lockfile.name.startswith("requirements") and lockfile.suffix == ".txt":
        reader = _requirements
    if reader is None:
        return DependencyGraph()
    try:
        return reader(lockfile, lockfile.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # malformed lockfile: no path information, the scan still runs
        return DependencyGraph()
