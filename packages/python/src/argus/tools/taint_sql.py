"""SQL injection across lines: lightweight intra-function taint tracking for Python (#183).

The line rules in ``sql-injection.yaml`` need the SQL and the user input on one line. Real code
splits them::

    name = request.args["name"]                                  # source
    query = "SELECT * FROM users WHERE name = '" + name + "'"    # propagation
    cursor.execute(query)                                        # sink

This check parses each Python file with ``ast`` (nothing is executed) and, inside every function,
follows request input through assignments, concatenation, f-strings, ``.format``, ``%`` and
``join`` to SQL execution calls. Casts (``int``, ``float``, ``uuid.UUID``…) and the early-exit
allowlist pattern (``if col not in ALLOWED: return``) clear the taint; parameterized calls
(``execute("… %s", (x,))``) are safe. Only flows that cross lines are reported: same-line string
building is already covered by the line rules.

JavaScript / TypeScript are not covered yet (they need a parser; see #183).
"""

from __future__ import annotations

import ast
import asyncio
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from argus_languages.noise import path_context

from argus.models import Finding, ScanResult, ScanType, Severity

TOOL_NAME = "argus-taint-sql"
_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".tox",
        "site-packages",
    }
)
_MAX_FILE = 1024 * 1024

# request.<attr> (Flask, Django, Starlette / FastAPI, DRF, Bottle, Falcon, aiohttp)
_REQUEST_ATTRS = frozenset(
    {
        "args",
        "form",
        "values",
        "json",
        "data",
        "files",
        "cookies",
        "headers",
        "GET",
        "POST",
        "COOKIES",
        "META",
        "body",
        "query_params",
        "path_params",
        "query",
        "params",
        "match_info",
        "query_string",
        "get_json",
        "get_data",
        "stream",
        "media",
    }
)
_REQUEST_NAMES = frozenset({"request", "req", "self.request"})
_ROUTE_DECORATORS = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "api_route",
        "websocket",
        "api_view",
        "action",
    }
)
_NOT_INPUT_PARAMS = frozenset(
    {
        "self",
        "cls",
        "request",
        "req",
        "db",
        "session",
        "conn",
        "connection",
        "cursor",
        "background_tasks",
        "response",
        "current_user",
        "user",
        "settings",
        "app",
    }
)
_SANITIZERS = frozenset({"int", "float", "bool", "UUID", "uuid4", "len", "abs", "round", "Decimal"})
# Calls whose first argument is SQL text.
_SQL_SINKS = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "raw",
        "extra",
        "RawSQL",
        "text",
        "read_sql",
        "read_sql_query",
        "mogrify",
        "exec_driver_sql",
    }
)


@dataclass
class _Origin:
    line: int
    what: str


@dataclass
class _State:
    tainted: dict[str, _Origin] = field(default_factory=dict)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _source_origin(node: ast.AST) -> _Origin | None:
    """request.args["x"], request.GET.get("x"), request.get_json()…"""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in _REQUEST_ATTRS:
            base = _dotted(sub.value)
            if base in _REQUEST_NAMES or base.endswith(".request"):
                return _Origin(getattr(sub, "lineno", 0), f"{base}.{sub.attr}")
    return None


def _taint_of(node: ast.AST | None, state: _State) -> _Origin | None:
    """The origin if this expression carries user input."""
    if node is None:
        return None
    if isinstance(node, ast.Call):
        name = _dotted(node.func).split(".")[-1]
        if name in _SANITIZERS:
            return None
    if isinstance(node, ast.Name):
        return state.tainted.get(node.id)
    origin = _source_origin(node)
    if origin:
        return origin
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.Lambda, ast.FunctionDef)):
            continue
        found = _taint_of(child, state)
        if found:
            return found
    return None


def _assigned_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _assigned_names(elt)]
    return []


_SAFE_PARAM_TYPES = frozenset(
    {"int", "float", "bool", "UUID", "uuid.UUID", "Decimal", "date", "datetime"}
)


def _params_with_defaults(args: ast.arguments) -> list[tuple[ast.arg, ast.expr | None]]:
    positional = [*args.posonlyargs, *args.args]
    padded: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults)) + list(
        args.defaults
    )
    return [*zip(positional, padded), *zip(args.kwonlyargs, args.kw_defaults)]


def _is_route_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if _dotted(target).split(".")[-1] in _ROUTE_DECORATORS:
            return True
    args = fn.args.args
    return bool(args) and args[0].arg == "request"  # Django function views


@dataclass
class TaintFinding:
    sink_line: int
    sink: str
    origin: _Origin
    variable: str


class _FunctionAnalyzer:
    def __init__(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.state = _State()
        self.findings: list[TaintFinding] = []
        if _is_route_handler(fn):
            for arg, default in _params_with_defaults(fn.args):
                annotation = ast.unparse(arg.annotation) if arg.annotation else ""
                if arg.arg in _NOT_INPUT_PARAMS or annotation in _SAFE_PARAM_TYPES:
                    continue  # framework objects, or values the framework already converted
                if default is not None and "Depends" in ast.unparse(default):
                    continue  # FastAPI dependency (db session, current user…)
                self.state.tainted[arg.arg] = _Origin(arg.lineno, f"route parameter '{arg.arg}'")
        self.visit_block(fn.body)

    def visit_block(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit_stmt(stmt)

    def visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # nested definitions are analysed on their own
        if isinstance(stmt, ast.If) and self._allowlist_guard(stmt):
            return
        # Sinks in this statement's own expressions (not in nested blocks: those are
        # checked when the block is visited, with the state at that point).
        self._check_sinks(stmt)
        if isinstance(stmt, ast.If):
            before = self._snapshot()
            self.visit_block(stmt.body)
            after_body = self._snapshot()
            self.state.tainted = dict(before)
            self.visit_block(stmt.orelse)
            self._merge(after_body)  # tainted on either path stays tainted
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                origin = _taint_of(stmt.iter, self.state)
                for name in _assigned_names(stmt.target):
                    self._set(name, origin)
            before = self._snapshot()
            self.visit_block(stmt.body)
            self._merge(before)  # the body may not run
            self.visit_block(stmt.orelse)
        elif isinstance(stmt, ast.Try):
            before = self._snapshot()
            self.visit_block(stmt.body)
            after_body = self._snapshot()
            for handler in stmt.handlers:
                self.state.tainted = {**before, **after_body}
                self.visit_block(handler.body)
                after_body = {**after_body, **self.state.tainted}
            self.state.tainted = after_body
            self.visit_block(stmt.orelse)
            self.visit_block(stmt.finalbody)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    for name in _assigned_names(item.optional_vars):
                        self.state.tainted.pop(name, None)
            self.visit_block(stmt.body)
        elif isinstance(stmt, ast.Assign):
            origin = _taint_of(stmt.value, self.state)
            for target in stmt.targets:
                for name in _assigned_names(target):
                    self._set(name, origin)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            for name in _assigned_names(stmt.target):
                self._set(name, _taint_of(stmt.value, self.state))
        elif isinstance(stmt, ast.AugAssign):
            origin = _taint_of(stmt.value, self.state)
            for name in _assigned_names(stmt.target):
                if origin:
                    self.state.tainted[name] = _Origin(origin.line, origin.what)

    def _snapshot(self) -> dict[str, _Origin]:
        return dict(self.state.tainted)

    def _merge(self, other: dict[str, _Origin]) -> None:
        for name, origin in other.items():
            self.state.tainted.setdefault(name, origin)

    def _set(self, name: str, origin: _Origin | None) -> None:
        if origin:
            self.state.tainted[name] = _Origin(origin.line, origin.what)
        else:
            self.state.tainted.pop(name, None)  # reassigned from something safe

    def _allowlist_guard(self, stmt: ast.If) -> bool:
        """`if x not in ALLOWED: return/raise/abort(...)` clears x afterwards."""
        test = stmt.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and isinstance(test.left, ast.Name)
        ):
            return False
        last = stmt.body[-1] if stmt.body else None
        exits = isinstance(last, (ast.Return, ast.Raise)) or (
            isinstance(last, ast.Expr)
            and isinstance(last.value, ast.Call)
            and _dotted(last.value.func).split(".")[-1] in {"abort", "HTTPException"}
        )
        if exits:
            self.state.tainted.pop(test.left.id, None)
            return True
        return False

    def _check_sinks(self, stmt: ast.stmt) -> None:
        for node in _own_expression_nodes(stmt):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            sink = _dotted(node.func).split(".")[-1]
            if sink not in _SQL_SINKS:
                continue
            query = node.args[0]
            # Same-line string building is the line rules' job; report flows through variables.
            if not isinstance(query, ast.Name):
                continue
            origin = self.state.tainted.get(query.id)
            if origin and origin.line != node.lineno:
                self.findings.append(TaintFinding(node.lineno, sink, origin, query.id))


def _own_expression_nodes(stmt: ast.stmt) -> list[ast.AST]:
    """Every node of a statement except those inside its nested statement blocks."""
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = [stmt]
    while stack:
        node = stack.pop()
        nodes.append(node)
        for name, value in ast.iter_fields(node):
            if name in {"body", "orelse", "finalbody", "handlers"} and isinstance(value, list):
                continue
            children = value if isinstance(value, list) else [value]
            stack.extend(c for c in children if isinstance(c, ast.AST))
    return nodes


def analyze_source(text: str) -> list[TaintFinding]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    findings: list[TaintFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_FunctionAnalyzer(node).findings)
    return findings


def _python_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        files.extend(Path(dirpath) / f for f in filenames if f.endswith(".py"))
    return files


def taint_findings(target: str) -> tuple[list[Finding], dict[str, object]]:
    root = Path(target)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []
    files = 0
    for path in _python_files(root):
        relative = path.relative_to(base).as_posix()
        if path_context(relative) in {"test", "docs"}:
            continue
        try:
            if path.stat().st_size > _MAX_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        for hit in analyze_source(text):
            findings.append(
                Finding(
                    title=(
                        f"User input reaches a SQL query: {hit.origin.what} (line {hit.origin.line}) "
                        f"→ {hit.sink}({hit.variable}) (line {hit.sink_line})"
                    ),
                    severity=Severity.HIGH,
                    scan_type=ScanType.SAST,
                    tool=TOOL_NAME,
                    file=relative,
                    line=hit.sink_line,
                    rule_id="python-sql-injection-taint",
                    confidence="high",
                    cwe="CWE-89",
                    description=(
                        f"`{hit.variable}` is built from {hit.origin.what} (line {hit.origin.line}) "
                        f"and passed to {hit.sink}() as SQL text on line {hit.sink_line}."
                    ),
                    fix_guidance=(
                        "Keep the SQL text constant and pass values as parameters: "
                        'cursor.execute("SELECT … WHERE name = %s", (name,)), '
                        'text("… WHERE name = :name").bindparams(name=name). For identifiers '
                        "(column / table names) check against an allowlist."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ],
                )
            )
    return findings, {"python_files": files}


async def run_taint_sql_check(target: str) -> ScanResult:
    result = ScanResult(tool=TOOL_NAME, scan_type=ScanType.SAST, target=target)
    findings, metadata = await asyncio.to_thread(taint_findings, target)
    result.findings.extend(findings)
    result.metadata.update(metadata)
    return result
