"""SQL injection across lines in JavaScript / TypeScript (#183), with tree-sitter.

Same idea as the Python check in ``taint_sql.py``: inside each function, follow request input
through declarations, destructuring, assignments, ``+=``, concatenation and template literals
to a SQL call, and report when the SQL text reaches the call **through a variable** built on
another line (same-line string building is the line rules' job)::

    const id = req.query.id;                               // source
    const sql = `DELETE FROM orders WHERE id = ${id}`;     // propagation
    await db.query(sql);                                   // sink

Number casts (``parseInt``, ``Number``, ``+x``…), escaping helpers and the early-exit
allowlist (``if (!ALLOWED.includes(col)) return``) clear the taint. Parameterized calls
(``db.query("… $1", [id])``) are safe because their SQL text is constant. Code is parsed,
never executed. Without tree-sitter installed the check is skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# request input: Express / Koa / Fastify / NestJS (req, request, ctx, ctx.request)
_SOURCE = re.compile(
    r"^(?:req|request|ctx\.request|ctx)\.(?:query|params|body|cookies|headers|rawBody)\b"
)
# Calls whose first argument is SQL text.
_SQL_SINKS = frozenset(
    {
        "query",
        "execute",
        "raw",
        "whereRaw",
        "orWhereRaw",
        "orderByRaw",
        "havingRaw",
        "joinRaw",
        "fromRaw",
        "groupByRaw",
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        "unsafe",
        "exec",
        "run",
        "all",
        "prepare",
    }
)
# exec / run / all / prepare are also child_process / RegExp / Promise methods: only count
# them on receivers that look like a database handle.
_AMBIGUOUS_SINKS = frozenset({"exec", "run", "all", "prepare"})
_DB_RECEIVER = re.compile(
    r"(?i)(?:^|\.)(?:db|database|conn(?:ection)?|client|pool|sqlite|stmt|sql|knex|pg|mysql|tx|trx)$"
)
_SANITIZERS = frozenset(
    {
        "parseInt",
        "parseFloat",
        "Number",
        "Boolean",
        "BigInt",
        "Math.floor",
        "Math.round",
        "Math.trunc",
        "Math.abs",
        "Number.parseInt",
        "Number.parseFloat",
        "escape",
        "mysql.escape",
        "connection.escape",
        "pool.escape",
        "SqlString.escape",
        "sqlstring.escape",
        "pgFormat",
        "format.literal",
        "escapeLiteral",
        "escapeIdentifier",
        "uuidValidate",
    }
)
# NestJS handler parameters bound to request input: @Query('id') id, @Body() dto, @Req() req…
_NEST_INPUT_DECORATOR = re.compile(
    r"^@(?:Query|Param|Body|Headers|Req|Request|Cookies|Ip|HostParam)\b"
)
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
)


@dataclass
class Origin:
    line: int
    what: str


@dataclass
class JsTaintFinding:
    sink_line: int
    sink: str
    origin: Origin
    variable: str


@dataclass
class _State:
    tainted: dict[str, Origin] = field(default_factory=dict)


def _parser(dialect: str) -> Any | None:
    try:
        import tree_sitter_javascript
        import tree_sitter_typescript
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    if dialect == "tsx":
        lang = tree_sitter_typescript.language_tsx()
    elif dialect == "typescript":
        lang = tree_sitter_typescript.language_typescript()
    else:
        lang = tree_sitter_javascript.language()
    return Parser(Language(lang))


def available() -> bool:
    return _parser("javascript") is not None


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _line(node: Any) -> int:
    return int(node.start_point[0]) + 1


class _Analyzer:
    def __init__(self) -> None:
        self.state = _State()
        self.findings: list[JsTaintFinding] = []

    def seed_parameters(self, function: Any) -> None:
        """NestJS handlers receive request input as decorated parameters."""
        params = function.child_by_field_name("parameters")
        for param in params.named_children if params is not None else []:
            decorators = [c for c in param.named_children if c.type == "decorator"]
            decorator = next((d for d in decorators if _NEST_INPUT_DECORATOR.match(_text(d))), None)
            if decorator is None:
                continue
            pattern = param.child_by_field_name("pattern") or next(
                (c for c in param.named_children if c.type in {"identifier", "object_pattern"}),
                None,
            )
            for name in self._names(pattern):
                self.state.tainted[name] = Origin(_line(param), f"{_text(decorator)} {name}")

    # --- expressions -----------------------------------------------------------------

    def taint_of(self, node: Any) -> Origin | None:
        if node is None or node.type in _FUNCTION_TYPES:
            return None
        if node.type in {"member_expression", "subscript_expression"} and _SOURCE.match(
            _text(node)
        ):
            return Origin(_line(node), _text(node))
        if node.type == "identifier":
            return self.state.tainted.get(_text(node))
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if _text(callee) in _SANITIZERS:
                return None
        if node.type == "unary_expression" and _text(node).startswith(("+", "-", "~")):
            return None
        for child in node.named_children:
            origin = self.taint_of(child)
            if origin:
                return origin
        return None

    @staticmethod
    def _names(pattern: Any) -> list[str]:
        if pattern is None:
            return []
        if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
            return [_text(pattern)]
        names: list[str] = []
        for child in pattern.named_children:
            if child.type == "pair_pattern":
                names.extend(_Analyzer._names(child.child_by_field_name("value")))
            elif child.type in {"assignment_pattern", "object_assignment_pattern"}:
                names.extend(
                    _Analyzer._names(child.child_by_field_name("left") or child.named_children[0])
                )
            else:
                names.extend(_Analyzer._names(child))
        return names

    def _set(self, names: list[str], origin: Origin | None) -> None:
        for name in names:
            if origin:
                self.state.tainted[name] = Origin(origin.line, origin.what)
            else:
                self.state.tainted.pop(name, None)

    # --- statements --------------------------------------------------------------------

    def block(self, node: Any) -> None:
        for child in node.named_children:
            self.statement(child)

    def statement(self, node: Any) -> None:
        kind = node.type
        if kind in _FUNCTION_TYPES or kind in {"class_declaration", "class"}:
            return  # analysed on their own
        if kind in {"lexical_declaration", "variable_declaration"}:
            for decl in node.named_children:
                if decl.type == "variable_declarator":
                    value = decl.child_by_field_name("value")
                    self._sinks(value)
                    self._set(self._names(decl.child_by_field_name("name")), self.taint_of(value))
            return
        if kind == "if_statement":
            self._sinks(node.child_by_field_name("condition"))
            if self._allowlist_guard(node):
                return
            before = dict(self.state.tainted)
            self.statement(node.child_by_field_name("consequence"))
            after_then = dict(self.state.tainted)
            self.state.tainted = dict(before)
            alternative = node.child_by_field_name("alternative")
            if alternative is not None:
                self.statement(alternative)
            self.state.tainted.update(after_then)  # tainted on either path
            return
        if kind in {"statement_block", "else_clause", "program"}:
            self.block(node)
            return
        if kind in {
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "try_statement",
            "catch_clause",
            "finally_clause",
            "switch_statement",
            "switch_body",
            "switch_case",
            "switch_default",
            "labeled_statement",
        }:
            for child in node.named_children:
                if child.type in {
                    "statement_block",
                    "catch_clause",
                    "finally_clause",
                    "switch_body",
                    "switch_case",
                    "switch_default",
                    "expression_statement",
                    "if_statement",
                    "lexical_declaration",
                    "variable_declaration",
                    "return_statement",
                } or child.type.endswith("_statement"):
                    self.statement(child)
                else:
                    self._sinks(child)
            return
        if kind == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is not None and expr.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
                self._sinks(right)
                if left is not None and left.type == "identifier":
                    origin = self.taint_of(right)
                    if expr.type == "augmented_assignment_expression":
                        origin = origin or self.state.tainted.get(_text(left))
                    self._set([_text(left)], origin)
                return
            self._sinks(expr)
            return
        self._sinks(node)

    def _allowlist_guard(self, node: Any) -> bool:
        """`if (!ALLOWED.includes(x)) return/throw` clears x afterwards."""
        cond_node = node.child_by_field_name("condition")
        while (
            cond_node is not None
            and cond_node.type == "parenthesized_expression"
            and cond_node.named_children
        ):
            cond_node = cond_node.named_children[0]
        cond = _text(cond_node).strip()
        m = re.fullmatch(r"!\s*[\w.$]+\.(?:includes|has)\(\s*([A-Za-z_$][\w$]*)\s*\)", cond)
        consequence = node.child_by_field_name("consequence")
        if not m or consequence is None:
            return False
        body = (
            consequence.named_children if consequence.type == "statement_block" else [consequence]
        )
        last = body[-1] if body else None
        if last is not None and last.type in {"return_statement", "throw_statement"}:
            self.state.tainted.pop(m.group(1), None)
            return True
        return False

    def _sinks(self, node: Any) -> None:
        if node is None:
            return
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in _FUNCTION_TYPES:
                continue
            if current.type == "call_expression":
                self._check_call(current)
            stack.extend(current.named_children)

    def _check_call(self, call: Any) -> None:
        callee = call.child_by_field_name("function")
        if callee is None or callee.type != "member_expression":
            return
        prop = _text(callee.child_by_field_name("property"))
        if prop not in _SQL_SINKS:
            return
        receiver = _text(callee.child_by_field_name("object"))
        if prop in _AMBIGUOUS_SINKS and not _DB_RECEIVER.search(receiver):
            return
        args = call.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        # Same-line string building is the line rules' job; report flows through variables.
        if first is None or first.type != "identifier":
            return
        origin = self.state.tainted.get(_text(first))
        if origin and origin.line != _line(call):
            self.findings.append(JsTaintFinding(_line(call), prop, origin, _text(first)))


def analyze_js_source(text: str, dialect: str = "javascript") -> list[JsTaintFinding]:
    parser = _parser(dialect)
    if parser is None:
        return []
    tree = parser.parse(text.encode("utf-8", "replace"))
    findings: list[JsTaintFinding] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in _FUNCTION_TYPES or node.type == "program":
            body = node.child_by_field_name("body") if node.type != "program" else node
            if body is not None:
                analyzer = _Analyzer()
                if node.type != "program":
                    analyzer.seed_parameters(node)
                if body.type in {"statement_block", "program"}:
                    analyzer.block(body)
                else:  # concise arrow body: (x) => db.query(x)
                    analyzer._sinks(body)
                findings.extend(analyzer.findings)
        stack.extend(node.named_children)
    unique = {(f.sink_line, f.variable): f for f in findings}
    return sorted(unique.values(), key=lambda f: f.sink_line)


def dialect_for(path: str) -> str | None:
    lower = path.lower()
    if lower.endswith((".min.js", ".d.ts")):
        return None
    if lower.endswith(".tsx"):
        return "tsx"
    if lower.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if lower.endswith((".js", ".mjs", ".cjs", ".jsx")):
        return "javascript"
    return None
