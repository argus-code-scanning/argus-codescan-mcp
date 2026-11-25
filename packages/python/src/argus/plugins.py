"""Scan plugins: installed packages can add ``argus scan <name>`` subcommands.

A package registers an object (or a class with a no-argument constructor) in the
``argus.scan_plugins`` entry point group::

    [project.entry-points."argus.scan_plugins"]
    nginx = "my_package.nginx:plugin"

The object provides ``name``, ``help``, ``add_arguments(parser)`` and
``async run(target, args, timeout) -> list[ScanResult]``. Results go through the normal
report, policy, ``--fail-on`` and ``--upload`` path. Plugins can't replace built-in scan types,
and one that fails to load prints a warning instead of breaking the CLI.
"""

from __future__ import annotations

import argparse
import sys
from functools import lru_cache
from importlib.metadata import entry_points
from typing import Any, Protocol, runtime_checkable

from argus.models import ScanResult

GROUP = "argus.scan_plugins"


@runtime_checkable
class ScanPlugin(Protocol):
    name: str
    help: str

    def add_arguments(self, parser: argparse.ArgumentParser) -> None: ...

    async def run(
        self, target: str, args: argparse.Namespace, timeout: int
    ) -> list[ScanResult]: ...


def _instantiate(obj: Any) -> Any:
    return obj() if isinstance(obj, type) else obj


@lru_cache(maxsize=1)
def load_scan_plugins() -> dict[str, ScanPlugin]:
    plugins: dict[str, ScanPlugin] = {}
    for ep in entry_points(group=GROUP):
        try:
            plugin = _instantiate(ep.load())
        except Exception as exc:  # a broken plugin must not break the CLI
            print(f"argus: could not load scan plugin {ep.name!r}: {exc}", file=sys.stderr)
            continue
        if not isinstance(plugin, ScanPlugin):
            print(f"argus: scan plugin {ep.name!r} is missing name/help/run", file=sys.stderr)
            continue
        plugins.setdefault(plugin.name, plugin)
    return plugins


def register_plugin_parsers(
    scan_sub: Any, add_common: Any, builtin: set[str]
) -> dict[str, ScanPlugin]:
    """Add a subparser per plugin (skipping names that clash with built-in scan types)."""
    added: dict[str, ScanPlugin] = {}
    for name, plugin in load_scan_plugins().items():
        if name in builtin:
            print(f"argus: scan plugin {name!r} clashes with a built-in scan type", file=sys.stderr)
            continue
        parser = scan_sub.add_parser(name, help=plugin.help)
        add_common(parser, paths_file=False)
        plugin.add_arguments(parser)
        added[name] = plugin
    return added
